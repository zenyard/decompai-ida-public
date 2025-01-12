import importlib.resources
import typing as ty
from contextlib import asynccontextmanager
from dataclasses import dataclass

import anyio
import typing_extensions as tye
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import (
    QApplication,
    QGraphicsColorizeEffect,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QProgressBar,
    QStatusBar,
    QWidget,
)

from decompai_ida import assets, ida_tasks

_current_widget: ty.Optional["_StatusBarWidget"] = None
"Current widget in status bar, only present to allow interactive access"


@dataclass(frozen=True)
class StatusBarWidgetState:
    text: str
    progress: ty.Union[ty.Literal["started"], ty.Optional[int]] = None
    warning: ty.Optional[str] = None
    enabled: bool = True


@asynccontextmanager
async def status_bar_widget() -> ty.AsyncIterator["StatusBarWidgetProxy"]:
    """
    Context manager adding widget to status bar, yielding an object to update
    it from async code.
    """

    global _current_widget

    def setup_sync():
        status_bar = _find_status_bar_sync()
        widget = _StatusBarWidget()
        status_bar.addPermanentWidget(widget)
        return status_bar, widget

    status_bar, widget = await ida_tasks.run_ui(setup_sync)

    try:
        _current_widget = widget
        yield StatusBarWidgetProxy(widget)
    finally:
        _current_widget = None
        with anyio.CancelScope(shield=True):
            await ida_tasks.run_ui(status_bar.removeWidget, widget)


class StatusBarWidgetProxy:
    def __init__(self, widget: "_StatusBarWidget"):
        self._widget = widget

    async def set_state(self, state: StatusBarWidgetState):
        await ida_tasks.run_ui(self._widget.set_state, state)


class _StatusBarWidget(QWidget):
    def __init__(self):
        super().__init__()

        self.setFixedWidth(320)

        # HBoxLayout
        self._hbox = QHBoxLayout()
        self.setLayout(self._hbox)
        self._hbox.setContentsMargins(4, 0, 4, 1)
        self._hbox.setSpacing(4)

        # Zenyard icon
        self._grey_icon_effect = QGraphicsColorizeEffect()
        self._grey_icon_effect.setColor(Qt.gray)
        self._icon = QLabel()
        self._hbox.addWidget(self._icon)
        self._icon.setPixmap(_load_icon("zenyard_icon.png"))
        self._icon.setFixedSize(18, 18)
        self._icon.setScaledContents(True)
        self._icon.setGraphicsEffect(self._grey_icon_effect)

        # Warning icon
        self._warning_icon = QLabel()
        self._hbox.addWidget(self._warning_icon)
        self._warning_icon.setPixmap(_load_icon("warning_icon.png"))
        self._warning_icon.setFixedSize(18, 18)
        self._warning_icon.setScaledContents(True)

        # Label
        self._label = QLabel()
        self._hbox.addWidget(self._label)
        self._label.setAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )

        # Progress bar
        self._progress_bar = QProgressBar()
        self._hbox.addWidget(self._progress_bar)
        self._progress_bar.setFixedSize(100, 18)

        self.set_state(StatusBarWidgetState(text=""))

    def set_state(self, state: StatusBarWidgetState):
        self._label.setText(state.text)

        if state.enabled:
            self._grey_icon_effect.setStrength(0.0)
        else:
            self._grey_icon_effect.setStrength(0.7)

        if state.warning is not None:
            self._warning_icon.setVisible(True)
            self._warning_icon.setToolTip(state.warning)
        else:
            self._warning_icon.setVisible(False)

        if state.progress == "started":
            self._progress_bar.setVisible(True)
            self._progress_bar.setRange(0, 0)
            self._progress_bar.setValue(0)
        elif isinstance(state.progress, int):
            self._progress_bar.setVisible(True)
            self._progress_bar.setRange(0, 100)
            self._progress_bar.setValue(state.progress)
        elif state.progress is None:
            self._progress_bar.setVisible(False)
        else:
            _: tye.Never = state.progress


def _load_icon(file_name: str) -> QPixmap:
    with importlib.resources.path(assets, file_name) as file_path:
        return QPixmap(str(file_path))


def _find_status_bar_sync() -> QStatusBar:
    for widget in QApplication.topLevelWidgets():
        if isinstance(widget, QMainWindow):
            return widget.statusBar()
    raise Exception("Can't find status bar")
