#!/usr/bin/env python3
"""Pinger — индикатор реального доступа в интернет.

Почему не ICMP: VPN/прокси с TUN-интерфейсом (Happ, sing-box, xray и т.п.)
отвечают на ping собственным сетевым стеком, не выпуская пакет наружу.
Получаются стабильные 0.1 мс при полностью мёртвом интернете.
Поэтому проверка идёт настоящим HTTP-запросом с проверкой тела ответа:
так видно и обрыв связи, и captive portal, и подмену DNS.
"""

import json
import math
import os
import sys
import time
from collections import deque

from PyQt5.QtCore import (QElapsedTimer, QObject, QPointF, QRectF, Qt, QTimer,
                          QUrl, pyqtSignal)
from PyQt5.QtGui import (QColor, QFont, QIcon, QPainter, QPalette, QPen,
                         QPixmap, QPolygonF)
from PyQt5.QtNetwork import (QNetworkAccessManager, QNetworkReply,
                             QNetworkRequest, QTcpSocket)
from PyQt5.QtWidgets import (QApplication, QComboBox, QFrame,
                             QGridLayout, QHBoxLayout, QLabel, QMenu,
                             QPushButton, QSizePolicy, QSystemTrayIcon,
                             QVBoxLayout, QWidget)

APP_NAME = "Pinger"

DEFAULT_CONFIG = {
    "interval_ms": 5000,
    # Таймаут большой намеренно: на мобильной связи ответ может прийти через
    # минуту (очереди в модеме/базовой станции), и это ценный замер, а не сбой.
    "timeout_ms": 60000,
    # Запрос без ответа дольше этого — цель «висит», не дожидаясь таймаута.
    "hang_ms": 10000,
    "history": 1200,
    # Интерфейс для графика трафика в трее; пусто — берётся из маршрута по умолчанию.
    "wan_interface": "",
    "targets": [
        {
            "name": "Cloudflare",
            "url": "https://cloudflare.com/cdn-cgi/trace",
            "expect_status": 200,
            "expect_body": "fl=",
            "color": "#f6821f",
        },
        {
            "name": "Google",
            "url": "http://connectivitycheck.gstatic.com/generate_204",
            "expect_status": 204,
            "expect_body": "",
            "color": "#4285f4",
        },
        {
            "name": "Firefox",
            "url": "http://detectportal.firefox.com/success.txt",
            "expect_status": 200,
            "expect_body": "success",
            "color": "#12b886",
        },
    ],
}

# ok       — ответ пришёл и совпал с ожидаемым
# bad      — соединение есть, но содержимое чужое (captive portal, подмена)
# fail     — соединения нет (таймаут, отказ, DNS)
# hang     — запрос ушёл, ответа нет дольше hang_ms, но и таймаута ещё нет
STATE_COLORS = {
    "ok": "#2ecc71",
    "degraded": "#f1c40f",
    "portal": "#e67e22",
    "down": "#e74c3c",
    "unknown": "#95a5a6",
    "paused": "#7f8c8d",
    "bad": "#e67e22",
    "fail": "#e74c3c",
    "hang": "#9b59b6",
}

STATE_TEXT = {
    "ok": "Интернет работает",
    "degraded": "Связь частичная",
    "portal": "Ответ подменён (портал/DNS)",
    "down": "Интернета нет",
    "unknown": "Проверка…",
    "paused": "Пауза",
    "hang": "Связь висит",
}


def config_path():
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "pinger", "config.json")


def load_config():
    path = config_path()
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    try:
        with open(path, "r", encoding="utf-8") as fh:
            user = json.load(fh)
        if isinstance(user, dict):
            cfg.update(user)
    except FileNotFoundError:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(DEFAULT_CONFIG, fh, ensure_ascii=False, indent=2)
        except OSError:
            pass
    except (ValueError, OSError) as exc:
        print(f"{APP_NAME}: не читается {path}: {exc}", file=sys.stderr)
    if not cfg.get("targets"):
        cfg["targets"] = DEFAULT_CONFIG["targets"]
    return cfg


def fmt_ms(ms):
    if ms is None:
        return "—"
    if ms < 1:
        return "<1 мс"
    if ms >= 10000:
        return f"{ms / 1000:.0f} с"
    return f"{ms:.0f} мс" if ms >= 10 else f"{ms:.1f} мс"


def fmt_rate(bps):
    if bps is None:
        return "—"
    for unit, div in (("МБ/с", 1 << 20), ("КБ/с", 1 << 10)):
        if bps >= div:
            value = bps / div
            return f"{value:.0f} {unit}" if value >= 10 else f"{value:.1f} {unit}"
    return f"{bps:.0f} Б/с"


def fmt_span(sec):
    sec = int(sec)
    if sec < 60:
        return f"{sec} с"
    if sec < 3600:
        return f"{sec // 60} мин {sec % 60} с"
    return f"{sec // 3600} ч {(sec % 3600) // 60} мин"


def fmt_ago(sec):
    """Подпись оси времени: «сейчас», «-30с», «-2м», «-1м30с»."""
    if sec <= 0:
        return "сейчас"
    if sec < 60:
        return f"-{sec:.0f}с"
    minutes, seconds = divmod(int(sec), 60)
    return f"-{minutes}м" if seconds == 0 else f"-{minutes}м{seconds}с"


def nice_ceil(value):
    """Округление верха шкалы вверх до «красивого» значения."""
    if value <= 0:
        return 100.0
    exp = math.floor(math.log10(value))
    frac = value / (10 ** exp)
    for step in (1, 1.5, 2, 3, 5, 7.5, 10):
        if frac <= step:
            return step * (10 ** exp)
    return 10 ** (exp + 1)


class Target:
    """Одна проверяемая цель и её история замеров."""

    def __init__(self, spec, history):
        self.kind = spec.get("type", "http")
        self.url = spec.get("url", "")
        self.host = spec.get("host", "")
        self.port = int(spec.get("port", 80))
        if self.kind == "tcp":
            self.name = spec.get("name") or f"{self.host}:{self.port}"
        else:
            self.name = spec.get("name") or self.url
        self.expect_status = int(spec.get("expect_status", 200))
        self.expect_body = spec.get("expect_body") or ""
        self.color = QColor(spec.get("color", "#4c8bf5"))
        self.samples = deque(maxlen=history)  # (ts, ms|None, state, detail)
        self.inflight = False
        self.pending_since = None  # time.time() отправки текущего запроса
        self.hang_ms = 10000

    @property
    def last(self):
        return self.samples[-1] if self.samples else None

    @property
    def hang_age(self):
        """Сколько секунд висит текущий запрос, если дольше hang_ms, иначе None."""
        if self.pending_since is None:
            return None
        age = time.time() - self.pending_since
        return age if age * 1000 >= self.hang_ms else None

    @property
    def state(self):
        if self.hang_age is not None:
            return "hang"
        return self.samples[-1][2] if self.samples else None

    def add(self, ms, state, detail):
        self.samples.append((time.time(), ms, state, detail))

    def window_stats(self):
        """Средняя задержка и доля потерь по сохранённой истории."""
        oks = [s[1] for s in self.samples if s[2] == "ok" and s[1] is not None]
        avg = sum(oks) / len(oks) if oks else None
        loss = 1.0 - (len(oks) / len(self.samples)) if self.samples else 0.0
        return avg, loss


class TcpProbe(QObject):
    """Проверка «открыт ли TCP-порт» — для роутера или конкретного сервиса."""

    done = pyqtSignal(str, object, str)

    def __init__(self, host, port, timeout_ms, parent=None):
        super().__init__(parent)
        self._fired = False
        self.elapsed = QElapsedTimer()
        self.sock = QTcpSocket(self)
        self.sock.connected.connect(self._on_connected)
        self.sock.errorOccurred.connect(self._on_error)
        QTimer.singleShot(timeout_ms, self._on_timeout)
        self.elapsed.start()
        self.sock.connectToHost(host, port)

    def _emit(self, state, ms, detail):
        if self._fired:
            return
        self._fired = True
        self.sock.abort()
        self.done.emit(state, ms, detail)
        self.deleteLater()

    def _on_connected(self):
        ms = self.elapsed.elapsed()
        self._emit("ok", float(ms), fmt_ms(ms))

    def _on_error(self, _err):
        self._emit("fail", None, self.sock.errorString())

    def _on_timeout(self):
        self._emit("fail", None, "таймаут")


def default_route_iface():
    """Интерфейс маршрута по умолчанию из таблицы main.

    /proc/net/route показывает только main, поэтому tun0 прокси (Happ ставит
    свой default в отдельную таблицу 2022) сюда не попадает — получаем
    настоящий WAN, через который идёт уже зашифрованный трафик прокси.
    """
    best = None
    try:
        with open("/proc/net/route", encoding="ascii") as fh:
            next(fh, None)
            for line in fh:
                f = line.split()
                if len(f) < 8 or f[1] != "00000000" or f[7] != "00000000":
                    continue
                if not int(f[3], 16) & 1:  # RTF_UP
                    continue
                metric = int(f[6])
                if best is None or metric < best[0]:
                    best = (metric, f[0])
    except OSError:
        pass
    return best[1] if best else None


def iface_counters(iface):
    """(rx_bytes, tx_bytes) интерфейса из /proc/net/dev или None."""
    try:
        with open("/proc/net/dev", encoding="ascii") as fh:
            for line in fh:
                name, sep, rest = line.partition(":")
                if sep and name.strip() == iface:
                    f = rest.split()
                    return int(f[0]), int(f[8])
    except (OSError, ValueError, IndexError):
        pass
    return None


# Одиночная секунда «ушёл ACK, ничего не пришло» — норма; мёртвым считаем
# приём, нулевой подряд хотя бы столько секунд при идущей передаче.
RX_DEAD_MIN_SEC = 3


def rx_dead_mask(samples):
    """Для каждого замера: входит ли он в серию «передача есть, приём 0»."""
    mask = [False] * len(samples)
    start = None
    for i in range(len(samples) + 1):
        s = samples[i] if i < len(samples) else None
        if s is not None and s[1] == 0:
            if start is None:
                start = i
            continue
        if start is not None:
            run = samples[start:i]
            if len(run) >= RX_DEAD_MIN_SEC and any(r[2] > 0 for r in run):
                mask[start:i] = [True] * len(run)
            start = None
    return mask


class TrafficMeter(QObject):
    """Скорость приёма/передачи через WAN-интерфейс, замер раз в секунду.

    Читаются только файлы procfs — это мгновенно и не блокирует цикл Qt.
    """

    updated = pyqtSignal()

    def __init__(self, iface="", history=3600, parent=None):
        super().__init__(parent)
        self.fixed_iface = iface or None
        self.iface = None
        self.samples = deque(maxlen=history)  # (ts, rx Б/с|None, tx Б/с|None)
        self._prev = None  # (iface, monotonic, rx, tx)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.tick)
        self.timer.start(1000)
        self.tick()

    @property
    def last(self):
        return self.samples[-1] if self.samples else None

    def tick(self):
        iface = self.fixed_iface or default_route_iface()
        counters = iface_counters(iface) if iface else None
        self.iface = iface
        if counters is None:
            self._prev = None
            self.samples.append((time.time(), None, None))
            self.updated.emit()
            return
        now = time.monotonic()
        prev, self._prev = self._prev, (iface, now, *counters)
        # Первый замер, смена интерфейса или сброс счётчиков (переподключение
        # ppp) — скорость посчитать не из чего, ждём следующего тика.
        if prev is None or prev[0] != iface or counters[0] < prev[2] \
                or counters[1] < prev[3] or now <= prev[1]:
            return
        dt = now - prev[1]
        self.samples.append((time.time(), (counters[0] - prev[2]) / dt,
                             (counters[1] - prev[3]) / dt))
        self.updated.emit()

    @property
    def rx_dead_sec(self):
        """Сколько секунд подряд (до текущего момента) приём строго нулевой,
        хотя передача была. Исходящий без входящего — интернет мёртв:
        пакеты уходят, ответов нет. 0 — такого сейчас нет."""
        tail = []
        for s in reversed(self.samples):
            if s[1] is None or s[1] > 0:
                break
            tail.append(s)
        if len(tail) < RX_DEAD_MIN_SEC or not any(s[2] > 0 for s in tail):
            return 0
        return len(tail)

    def window_stats(self, since):
        """Средние скорости приёма и передачи начиная с момента since."""
        live = [s for s in self.samples if s[0] >= since and s[1] is not None]
        if not live:
            return None, None
        return (sum(s[1] for s in live) / len(live),
                sum(s[2] for s in live) / len(live))

    def summary(self):
        last = self.last
        if not self.iface or last is None or last[1] is None:
            return "Трафик: интерфейс не найден" if not self.iface \
                else f"Трафик {self.iface}: —"
        return (f"Трафик {self.iface}: ↓ {fmt_rate(last[1])} ↑ {fmt_rate(last[2])}"
                f" · шкала {fmt_rate(traffic_scale(list(self.samples)[-22:]))}"
                + (f"\n⚠ Входящий трафик на нуле {fmt_span(self.rx_dead_sec)}"
                   if self.rx_dead_sec else ""))


class Monitor(QObject):
    """Опрашивает цели, копит историю, считает общий вердикт."""

    updated = pyqtSignal()

    def __init__(self, cfg, parent=None):
        super().__init__(parent)
        self.interval_ms = int(cfg["interval_ms"])
        self.timeout_ms = int(cfg["timeout_ms"])
        self.hang_ms = int(cfg["hang_ms"])
        history = int(cfg["history"])
        self.targets = [Target(spec, history) for spec in cfg["targets"]]
        for target in self.targets:
            target.hang_ms = self.hang_ms
        self.overall = deque(maxlen=history)  # (ts, ms|None, state)
        self.state = "unknown"
        self.state_since = time.time()
        self.paused = False

        self.nam = QNetworkAccessManager(self)
        # Редиректы не глотаем: 30x — характерный признак captive portal.
        self.nam.setRedirectPolicy(QNetworkRequest.ManualRedirectPolicy)
        self.nam.setCache(None)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.tick)
        self.timer.start(self.interval_ms)
        QTimer.singleShot(0, self.tick)

    # --- опрос ---------------------------------------------------------

    def tick(self):
        if self.paused:
            return
        # Разносим запросы внутри интервала, чтобы не бить залпом.
        spread = min(300, self.interval_ms // max(1, len(self.targets)))
        for i, target in enumerate(self.targets):
            QTimer.singleShot(i * spread, lambda t=target: self.probe(t))
        self._sample_overall()

    def probe_now(self):
        for target in self.targets:
            self.probe(target)

    def probe(self, target):
        if self.paused or target.inflight:
            return
        target.inflight = True
        target.pending_since = sent = time.time()
        # Переход в «висит» ловим отдельным таймером: ответа, который мог бы
        # вызвать пересчёт, как раз и нет.
        QTimer.singleShot(self.hang_ms, lambda t=target, s=sent: self._on_hang_check(t, s))
        if target.kind == "tcp":
            probe = TcpProbe(target.host, target.port, self.timeout_ms, self)
            probe.done.connect(
                lambda state, ms, detail, t=target: self._record(t, state, ms, detail))
            return

        req = QNetworkRequest(QUrl(target.url))
        req.setHeader(QNetworkRequest.UserAgentHeader, "Pinger/2 (Qt)")
        req.setAttribute(QNetworkRequest.CacheLoadControlAttribute,
                         QNetworkRequest.AlwaysNetwork)
        req.setAttribute(QNetworkRequest.CacheSaveControlAttribute, False)
        req.setTransferTimeout(self.timeout_ms)
        elapsed = QElapsedTimer()
        elapsed.start()
        reply = self.nam.get(req)
        reply.finished.connect(
            lambda r=reply, t=target, e=elapsed: self._on_reply(r, t, e))

    def _on_reply(self, reply, target, elapsed):
        ms = float(elapsed.elapsed())
        err = reply.error()
        status = reply.attribute(QNetworkRequest.HttpStatusCodeAttribute)
        # Тело читаем только у живого ответа: у оборванного QIODevice уже закрыт.
        body = "" if status is None else bytes(reply.readAll()).decode("utf-8", "replace")
        reply.deleteLater()

        if status is None:
            detail = "таймаут" if err == QNetworkReply.OperationCanceledError \
                else reply.errorString()
            self._record(target, "fail", None, detail)
        elif status != target.expect_status:
            self._record(target, "bad", ms, f"HTTP {status}")
        elif target.expect_body and target.expect_body not in body:
            self._record(target, "bad", ms, "чужой ответ")
        else:
            self._record(target, "ok", ms, fmt_ms(ms))

    def _on_hang_check(self, target, sent):
        if target.pending_since == sent:
            self._recompute()
            self.updated.emit()

    def _record(self, target, state, ms, detail):
        target.inflight = False
        target.pending_since = None
        target.add(ms, state, detail)
        self._recompute()
        self.updated.emit()

    # --- сводка --------------------------------------------------------

    def _recompute(self):
        if self.paused:
            new_state = "paused"
        else:
            states = [t.state for t in self.targets if t.state]
            if not states:
                new_state = "unknown"
            elif all(s == "ok" for s in states):
                new_state = "ok"
            elif any(s == "ok" for s in states):
                new_state = "degraded"
            elif any(s == "bad" for s in states):
                new_state = "portal"
            elif any(s == "hang" for s in states):
                new_state = "hang"
            else:
                new_state = "down"
        if new_state != self.state:
            self.state = new_state
            self.state_since = time.time()

    def _sample_overall(self):
        """Равномерный ряд для спарклайна в трее: лучшая задержка за тик."""
        # Висящая цель не в счёт: её последний «ok» уже устарел.
        best = [t.last[1] for t in self.targets
                if t.hang_age is None and t.last and t.last[2] == "ok"
                and t.last[1] is not None]
        self.overall.append((time.time(), min(best) if best else None, self.state))

    def set_paused(self, paused):
        self.paused = paused
        if paused:
            self.timer.stop()
        else:
            self.timer.start(self.interval_ms)
            QTimer.singleShot(0, self.tick)
        self._recompute()
        self.updated.emit()

    def summary(self):
        lines = [f"{STATE_TEXT.get(self.state, self.state)} · {fmt_span(time.time() - self.state_since)}"]
        for t in self.targets:
            last = t.last
            if t.hang_age is not None and not self.paused:
                lines.append(f"⏳ {t.name}: висит {fmt_span(t.hang_age)}")
                continue
            if not last:
                lines.append(f"{t.name}: —")
                continue
            mark = {"ok": "✓", "bad": "!", "fail": "✗"}.get(last[2], "?")
            lines.append(f"{mark} {t.name}: {last[3]}")
        return "\n".join(lines)


# Цвета как в сетевом апплете KDE (Breeze): приём синий, передача оранжевая.
RX_COLOR = "#1d99f3"
TX_COLOR = "#f39c1f"


# Нижняя граница автошкалы: при простое фоновые байты не растягиваются на всю высоту.
TRAFFIC_MIN_SCALE = 1024.0


def traffic_scale(samples):
    """Верх шкалы трафика — удвоенная средняя скорость за видимый период,
    так что средний уровень оказывается на середине полосы."""
    rates = [max(s[1], s[2]) for s in samples if s[1] is not None]
    avg = sum(rates) / len(rates) if rates else 0.0
    return max(TRAFFIC_MIN_SCALE, 2.0 * avg)


def draw_traffic(p, traffic, size, band_h):
    """Верхняя полоса иконки: трафик WAN, столбики по 2 px, каждый — 2 секунды.

    В столбик идёт максимум за его секунды: вопрос «шло ли хоть что-то»
    не должен размываться усреднением. Шкала линейная, от средней скорости
    за период; пики выше обрезаются. Любой ненулевой трафик даёт хотя бы
    1 px. Приём главнее: рисуется поверх передачи. Если передача есть,
    а приём строго нулевой (серией от RX_DEAD_MIN_SEC), столбик красный.
    """
    col_w, per_col = 2, 2
    base = QColor("#95a5a6")
    base.setAlpha(70)
    p.fillRect(0, band_h - 1, size, 1, base)
    data = list(traffic)[-(size // col_w) * per_col:]
    scale = traffic_scale(data)
    mask = rx_dead_mask(data)
    # Группируем с правого края, чтобы последний столбик был самым свежим.
    groups = []
    for end in range(len(data), 0, -per_col):
        idx = range(max(0, end - per_col), end)
        live = [data[i] for i in idx if data[i][1] is not None]
        if not live:
            groups.append(None)
            continue
        groups.append((max(s[1] for s in live), max(s[2] for s in live),
                       all(mask[i] for i in idx if data[i][1] is not None)))
    rx_color, tx_color = QColor(RX_COLOR), QColor(TX_COLOR)
    dead = QColor(STATE_COLORS["down"])
    dead.setAlpha(170)
    for n, group in enumerate(groups):
        if group is None:
            continue
        rx, tx, is_dead = group
        x = size - (n + 1) * col_w
        if is_dead:
            p.fillRect(x, 0, col_w, band_h, dead)
        for bps, color in ((tx, tx_color), (rx, rx_color)):
            if bps > 0:
                h = max(1, min(band_h, math.ceil(band_h * bps / scale)))
                p.fillRect(x, band_h - h, col_w, h, color)


# Точки пинга в трее: одинаковой высоты, ступень задержки — только цветом;
# нет ответа — цвет вердикта (висит / портал / нет интернета).
PING_TIERS = ((300.0, "#2ecc71"), (2000.0, "#f1c40f"), (math.inf, "#e67e22"))


def draw_ping_dots(p, series, size, top_y, height):
    """Ряд точек задержки: колонка в 1 px с шагом 2 px."""
    data = list(series)[-(size // 2):]
    for i, (_ts, ms, st) in enumerate(data):
        x = size - 1 - (len(data) - i) * 2
        if ms is None:
            color = STATE_COLORS.get(st, STATE_COLORS["down"])
        else:
            color = next(c for limit, c in PING_TIERS if ms < limit)
        p.fillRect(x, top_y, 1, height, QColor(color))


def tray_icon(state, series, traffic=(), size=22):
    """Иконка трея: трафик WAN сверху, ряд точек задержки, полоса статуса."""
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    # 22 px: трафик 0–13, зазор, точки пинга 15–17, зазор, статус 19–21.
    band_h = size - 8
    draw_traffic(p, traffic, size, band_h)
    draw_ping_dots(p, series, size, size - 7, 3)
    p.fillRect(0, size - 3, size, 3, QColor(STATE_COLORS.get(state, "#95a5a6")))
    p.end()
    return QIcon(pm)


def draw_time_grid(p, rect, plot, range_sec, grid_color, muted):
    """Вертикальная сетка и подписи оси времени (правый край — «сейчас»)."""
    # Шаг сетки берём круглый, чтобы подписи читались: 10с, 30с, 1м, 5м…
    step = next((s for s in (10, 15, 30, 60, 120, 300, 600)
                 if range_sec / s <= 8), 900)
    ago = 0
    while ago <= range_sec:
        x = plot.right() - ago / range_sec * plot.width()
        p.setPen(QPen(grid_color, 1, Qt.DotLine))
        p.drawLine(QPointF(x, plot.top()), QPointF(x, plot.bottom()))
        p.setPen(QPen(muted, 1))
        lx = min(max(x - 30, rect.left()), rect.right() - 60)
        p.drawText(QRectF(lx, rect.bottom() - 18, 60, 16),
                   Qt.AlignCenter, fmt_ago(ago))
        ago += step


def fmt_axis_rate(bps):
    """Подпись оси скорости: без десятичных, чтобы влезала в поле слева."""
    for unit, div in (("М", 1 << 20), ("К", 1 << 10)):
        if bps >= div:
            value = bps / div
            return f"{value:.0f}{unit}" if value >= 10 or value == int(value) \
                else f"{value:.1f}{unit}"
    return f"{bps:.0f}"


class TrafficChart(QWidget):
    """Скорость приёма/передачи через WAN — заливкой, как в апплете KDE."""

    def __init__(self, traffic, parent=None):
        super().__init__(parent)
        self.traffic = traffic
        self.range_sec = 120
        self.setMinimumHeight(140)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

    def set_range(self, seconds):
        self.range_sec = seconds
        self.update()

    def paintEvent(self, _event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        rect = QRectF(self.rect().adjusted(0, 0, -1, -1))
        p.fillRect(rect, self.palette().color(QPalette.Base))

        text_color = self.palette().color(QPalette.Text)
        grid_color = QColor(text_color)
        grid_color.setAlpha(38)
        muted = QColor(text_color)
        muted.setAlpha(150)

        left, right, top, bottom = 54.0, 32.0, 24.0, 30.0
        plot = QRectF(rect.left() + left, rect.top() + top,
                      rect.width() - left - right, rect.height() - top - bottom)
        if plot.width() < 30 or plot.height() < 30:
            return

        now = time.time()
        t0 = now - self.range_sec
        data = [s for s in self.traffic.samples if s[0] >= t0]
        peak = max((max(s[1], s[2]) for s in data if s[1] is not None), default=0.0)
        # В окне с подписанной осью пики не обрезаем: шкала по максимуму,
        # округлённая в тех единицах (К/М), в которых подписана ось.
        peak = max(peak, TRAFFIC_MIN_SCALE)
        div = 1 << 20 if peak >= 1 << 20 else 1 << 10
        ymax = nice_ceil(peak / div) * div

        small = QFont(self.font())
        small.setPointSizeF(max(7.0, self.font().pointSizeF() - 1.5))
        p.setFont(small)

        for i in range(5):
            frac = i / 4.0
            y = plot.bottom() - frac * plot.height()
            p.setPen(QPen(grid_color, 1))
            p.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
            p.setPen(QPen(muted, 1))
            p.drawText(QRectF(rect.left(), y - 8, left - 8, 16),
                       Qt.AlignRight | Qt.AlignVCenter, fmt_axis_rate(ymax * frac))
        p.setPen(QPen(muted, 1))
        p.drawText(QRectF(rect.left(), rect.top() + 2, left - 8, 14),
                   Qt.AlignRight | Qt.AlignVCenter, "Б/с")
        draw_time_grid(p, rect, plot, self.range_sec, grid_color, muted)

        if not data:
            p.setPen(QPen(muted, 1))
            p.drawText(plot, Qt.AlignCenter, "Нет данных" if self.traffic.iface
                       else "WAN-интерфейс не найден")
            return

        def to_x(ts):
            return plot.left() + (ts - t0) / self.range_sec * plot.width()

        def to_y(bps):
            return plot.bottom() - min(bps, ymax) / ymax * plot.height()

        # Передача есть, приём строго нулевой — ответов нет, подсвечиваем.
        dead = QColor(STATE_COLORS["down"])
        dead.setAlpha(60)
        col_w = max(1.0, plot.width() / self.range_sec)
        for (ts, _rx, _tx), is_dead in zip(data, rx_dead_mask(data)):
            if is_dead:
                p.fillRect(QRectF(to_x(ts) - col_w, plot.top(), col_w, plot.height()), dead)

        # Приём рисуем последним: он главный сигнал и не должен прятаться.
        for idx, color_name in ((2, TX_COLOR), (1, RX_COLOR)):
            color = QColor(color_name)
            fill = QColor(color)
            fill.setAlpha(90)
            segment = []
            for s in data + [(now, None, None)]:
                if s[1] is not None:
                    segment.append(QPointF(to_x(s[0]), to_y(s[idx])))
                    continue
                if len(segment) > 1:
                    area = QPolygonF(segment)
                    area.append(QPointF(segment[-1].x(), plot.bottom()))
                    area.append(QPointF(segment[0].x(), plot.bottom()))
                    p.setPen(Qt.NoPen)
                    p.setBrush(fill)
                    p.drawPolygon(area)
                    p.setPen(QPen(color, 1.5))
                    p.setBrush(Qt.NoBrush)
                    p.drawPolyline(QPolygonF(segment))
                segment = []


class ChartWidget(QWidget):
    """График задержек по всем целям + полоса сбоев под осью."""

    def __init__(self, monitor, parent=None):
        super().__init__(parent)
        self.monitor = monitor
        self.range_sec = 120
        self.setMinimumHeight(220)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

    def set_range(self, seconds):
        self.range_sec = seconds
        self.update()

    def paintEvent(self, _event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        rect = QRectF(self.rect().adjusted(0, 0, -1, -1))
        p.fillRect(rect, self.palette().color(QPalette.Base))

        text_color = self.palette().color(QPalette.Text)
        grid_color = QColor(text_color)
        grid_color.setAlpha(38)
        muted = QColor(text_color)
        muted.setAlpha(150)

        targets = self.monitor.targets
        band_h = len(targets) * 4
        left, right, top = 54.0, 32.0, 24.0
        bottom = 30.0 + band_h
        plot = QRectF(rect.left() + left, rect.top() + top,
                      rect.width() - left - right, rect.height() - top - bottom)
        if plot.width() < 30 or plot.height() < 30:
            return

        now = time.time()
        t0 = now - self.range_sec
        visible = [s[1] for t in targets for s in t.samples
                   if s[0] >= t0 and s[2] == "ok" and s[1] is not None]
        hanging = [(t, t.hang_age) for t in targets
                   if t.hang_age is not None and not self.monitor.paused]
        visible += [age * 1000 for _t, age in hanging]
        ymax = nice_ceil(max(visible)) if visible else 100.0

        small = QFont(self.font())
        small.setPointSizeF(max(7.0, self.font().pointSizeF() - 1.5))
        p.setFont(small)

        for i in range(5):
            frac = i / 4.0
            y = plot.bottom() - frac * plot.height()
            p.setPen(QPen(grid_color, 1))
            p.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
            p.setPen(QPen(muted, 1))
            p.drawText(QRectF(rect.left(), y - 8, left - 8, 16),
                       Qt.AlignRight | Qt.AlignVCenter, f"{ymax * frac:.0f}")
        p.setPen(QPen(muted, 1))
        p.drawText(QRectF(rect.left(), rect.top() + 2, left - 8, 14),
                   Qt.AlignRight | Qt.AlignVCenter, "мс")

        def to_x(ts):
            return plot.left() + (ts - t0) / self.range_sec * plot.width()

        def to_y(ms):
            return plot.bottom() - min(ms, ymax) / ymax * plot.height()

        draw_time_grid(p, rect, plot, self.range_sec, grid_color, muted)

        if not visible and not any(t.samples for t in targets):
            p.setPen(QPen(muted, 1))
            p.drawText(plot, Qt.AlignCenter, "Нет данных")
            return

        # Линии задержек: разрыв на каждом неудачном замере.
        for target in targets:
            segment = QPolygonF()
            for ts, ms, state, _detail in target.samples:
                if ts < t0:
                    continue
                if state == "ok" and ms is not None:
                    segment.append(QPointF(to_x(ts), to_y(ms)))
                else:
                    if segment.count() > 1:
                        p.setPen(QPen(target.color, 1.8))
                        p.drawPolyline(segment)
                    segment = QPolygonF()
            if segment.count() > 1:
                p.setPen(QPen(target.color, 1.8))
                p.drawPolyline(segment)
            last = target.last
            if last and last[2] == "ok" and last[1] is not None and last[0] >= t0:
                p.setBrush(target.color)
                p.setPen(Qt.NoPen)
                p.drawEllipse(QPointF(to_x(last[0]), to_y(last[1])), 3.0, 3.0)

        # Висящий запрос: пунктир от момента отправки, растущий вместе
        # с ожиданием, — «если ответ придёт сейчас, задержка будет такой».
        for target, age in hanging:
            start = max(target.pending_since, t0)
            p.setPen(QPen(target.color, 1.8, Qt.DashLine))
            p.drawLine(QPointF(to_x(start), to_y((start - target.pending_since) * 1000)),
                       QPointF(to_x(now), to_y(age * 1000)))
            p.setPen(QPen(QColor(STATE_COLORS["hang"]), 1))
            p.drawText(QRectF(plot.right() - 120, to_y(age * 1000) - 16, 116, 14),
                       Qt.AlignRight | Qt.AlignVCenter, f"ждём {fmt_span(age)}")

        # Полоса сбоев: своя строка на каждую цель.
        band_top = plot.bottom() + 6
        for idx, target in enumerate(targets):
            y = band_top + idx * 4
            for ts, _ms, state, _detail in target.samples:
                if ts < t0 or state == "ok":
                    continue
                p.fillRect(QRectF(to_x(ts) - 1.5, y, 3, 3),
                           QColor(STATE_COLORS.get(state, "#e74c3c")))


class MainWindow(QWidget):
    def __init__(self, monitor, traffic):
        super().__init__()
        self.monitor = monitor
        self.traffic = traffic
        self.setWindowTitle(f"{APP_NAME} — доступ в интернет")
        self.resize(820, 620)

        self.status_label = QLabel("Проверка…")
        font = QFont(self.font())
        font.setPointSizeF(font.pointSizeF() + 4)
        font.setBold(True)
        self.status_label.setFont(font)
        self.since_label = QLabel("")

        self.pause_btn = QPushButton("Пауза")
        self.pause_btn.setCheckable(True)
        self.pause_btn.toggled.connect(self._on_pause)
        now_btn = QPushButton("Проверить сейчас")
        now_btn.clicked.connect(monitor.probe_now)

        self.range_box = QComboBox()
        for label, secs in (("2 мин", 120), ("5 мин", 300), ("15 мин", 900),
                            ("30 мин", 1800), ("1 час", 3600)):
            self.range_box.addItem(label, secs)
        # Стартовый диапазон подбираем под интервал опроса: график бесполезен,
        # если в него попадает десяток точек.
        wanted = 40 * monitor.interval_ms / 1000
        self.range_box.setCurrentIndex(next(
            (i for i in range(self.range_box.count())
             if self.range_box.itemData(i) >= wanted),
            self.range_box.count() - 1))
        self.range_box.currentIndexChanged.connect(self._on_range)

        head = QHBoxLayout()
        head.addWidget(self.status_label)
        head.addWidget(self.since_label)
        head.addStretch(1)
        head.addWidget(QLabel("Окно:"))
        head.addWidget(self.range_box)
        head.addWidget(now_btn)
        head.addWidget(self.pause_btn)

        self.chart = ChartWidget(monitor)
        self.traffic_chart = TrafficChart(traffic)
        self.traffic_label = QLabel("")
        self.traffic_label.setTextFormat(Qt.RichText)
        self._on_range()

        self.legend = QGridLayout()
        self.legend.setHorizontalSpacing(14)
        self.legend.setVerticalSpacing(2)
        headers = ["", "Цель", "Сейчас", "Средняя", "Потери", "Ответ"]
        for col, title in enumerate(headers):
            label = QLabel(title)
            label.setStyleSheet("color: palette(mid);")
            self.legend.addWidget(label, 0, col)
        self.rows = []
        mono = QFont("monospace")
        for i, target in enumerate(monitor.targets, start=1):
            chip = QLabel()
            chip.setFixedSize(12, 12)
            chip.setStyleSheet(
                f"background:{target.color.name()}; border-radius:3px;")
            name = QLabel(target.name)
            cells = [QLabel("—") for _ in range(4)]
            for cell in cells:
                cell.setFont(mono)
            self.legend.addWidget(chip, i, 0)
            self.legend.addWidget(name, i, 1)
            for col, cell in enumerate(cells, start=2):
                self.legend.addWidget(cell, i, col)
            self.rows.append(cells)
        self.legend.setColumnStretch(5, 1)

        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)

        layout = QVBoxLayout(self)
        layout.addLayout(head)
        layout.addWidget(self.chart, 3)
        layout.addWidget(self.traffic_label)
        layout.addWidget(self.traffic_chart, 2)
        layout.addWidget(line)
        layout.addLayout(self.legend)

        monitor.updated.connect(self.refresh)
        traffic.updated.connect(self.refresh_traffic)
        self.refresh()
        self.refresh_traffic()

    def _on_range(self):
        secs = self.range_box.currentData()
        self.chart.set_range(secs)
        self.traffic_chart.set_range(secs)
        self.refresh_traffic()

    def refresh_traffic(self):
        if not self.isVisible() and self.traffic_label.text():
            return
        # Счётчик «висит N с» и пунктир должны тикать и без новых ответов.
        if any(t.hang_age is not None for t in self.monitor.targets):
            self.refresh()
        t = self.traffic
        last = t.last
        rx_now, tx_now = (last[1], last[2]) if last else (None, None)
        rx_avg, tx_avg = t.window_stats(time.time() - self.range_box.currentData())
        self.traffic_label.setText(
            f"<b>Трафик {t.iface or '—'}</b> &nbsp; "
            f"<span style='color:{RX_COLOR}'>■</span> приём {fmt_rate(rx_now)}"
            f" (средн. {fmt_rate(rx_avg)}) &nbsp; "
            f"<span style='color:{TX_COLOR}'>■</span> передача {fmt_rate(tx_now)}"
            f" (средн. {fmt_rate(tx_avg)})"
            + (f" &nbsp; <b style='color:{STATE_COLORS['down']}'>входящий на нуле"
               f" {fmt_span(t.rx_dead_sec)}</b>" if t.rx_dead_sec else ""))
        self.traffic_chart.update()

    def showEvent(self, event):
        super().showEvent(event)
        self.refresh_traffic()

    def _on_pause(self, checked):
        self.pause_btn.setText("Продолжить" if checked else "Пауза")
        self.monitor.set_paused(checked)

    def refresh(self):
        state = self.monitor.state
        color = STATE_COLORS.get(state, "#95a5a6")
        self.status_label.setText(STATE_TEXT.get(state, state))
        self.status_label.setStyleSheet(f"color: {color};")
        self.since_label.setText(
            f"· {fmt_span(time.time() - self.monitor.state_since)}")
        for target, cells in zip(self.monitor.targets, self.rows):
            last = target.last
            avg, loss = target.window_stats()
            if target.hang_age is not None and not self.monitor.paused:
                cells[0].setText(f"висит {fmt_span(target.hang_age)}")
                cells[0].setStyleSheet(f"color: {STATE_COLORS['hang']};")
                if last:
                    cells[3].setText(f"прошлый: {last[3]}")
            elif last:
                cells[0].setText(fmt_ms(last[1]) if last[2] == "ok" else "—")
                cells[0].setStyleSheet(
                    f"color: {STATE_COLORS.get(last[2], '#95a5a6')};")
                cells[3].setText(last[3])
            cells[1].setText(fmt_ms(avg))
            cells[2].setText(f"{loss * 100:.0f}%")
        self.chart.update()

    def closeEvent(self, event):
        # Окно только прячется — приложение живёт в трее.
        event.ignore()
        self.hide()


class TrayApp:
    def __init__(self, app, cfg):
        self.app = app
        self.monitor = Monitor(cfg)
        self.traffic = TrafficMeter(cfg.get("wan_interface") or "", parent=app)
        self.window = MainWindow(self.monitor, self.traffic)

        self.tray = QSystemTrayIcon()
        self.tray.setIcon(tray_icon("unknown", []))
        self.tray.activated.connect(self._on_activated)

        menu = QMenu()
        menu.addAction("Показать график", self.toggle_window)
        menu.addAction("Проверить сейчас", self.monitor.probe_now)
        menu.addSeparator()
        self.pause_action = menu.addAction("Пауза")
        self.pause_action.setCheckable(True)
        self.pause_action.toggled.connect(self.window.pause_btn.setChecked)
        self.window.pause_btn.toggled.connect(self.pause_action.setChecked)
        menu.addSeparator()
        menu.addAction("Выход", app.quit)
        self.tray.setContextMenu(menu)
        self.tray.setVisible(True)

        self.monitor.updated.connect(self.refresh)
        self.traffic.updated.connect(self.refresh)
        self.refresh()

    def refresh(self):
        self.tray.setIcon(tray_icon(self.monitor.state, self.monitor.overall,
                                    self.traffic.samples))
        self.tray.setToolTip(
            f"{self.monitor.summary()}\n{self.traffic.summary()}")

    def toggle_window(self):
        if self.window.isVisible():
            self.window.hide()
        else:
            self.window.show()
            self.window.raise_()
            self.window.activateWindow()

    def _on_activated(self, reason):
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            self.toggle_window()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setQuitOnLastWindowClosed(False)
    tray_app = TrayApp(app, load_config())
    if "--window" in sys.argv[1:] or not QSystemTrayIcon.isSystemTrayAvailable():
        tray_app.window.show()
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())
