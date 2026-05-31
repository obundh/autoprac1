# -*- coding: utf-8 -*-
"""Local pixel-detection mouse assistant learning example.

This app reads local screen pixels and helps move the mouse within a user
selected detection area. It does not send network requests, call service APIs,
store login credentials, bypass security controls, or automate final orders.
"""

from __future__ import annotations

import ctypes
import json
import os
import sys
import threading
import time
import tkinter as tk
from collections.abc import Callable
from ctypes import wintypes
from tkinter import colorchooser, filedialog, messagebox, ttk


NOTICE_TEXT = (
    "공개 사용 고지: 이 프로그램은 로컬 화면 픽셀 감지 기반 GUI 자동화 학습 예제입니다.\n"
    "네트워크 요청, API 호출, 로그인 정보 저장, 보안조치 우회 기능을 포함하지 않습니다.\n"
    "재판매, 대리예매, 다계정, 대량 확보, 암표 거래 목적 사용을 금지합니다.\n"
    "보안문자, 대기열, 본인인증, 매수 제한, 접근 제한, 결제 보안 절차 우회를 금지합니다.\n"
    "최종 결제/약관 동의/구매 확정/주문 제출 좌표의 자동 클릭은 절대 금지합니다."
)

APP_TITLE = "Local Pixel Mouse Assistant"
MIN_SCAN_INTERVAL_MS = 120
DEFAULT_SCAN_INTERVAL_MS = 250
MIN_PRE_CLICK_WAIT_MS = 250
DEFAULT_PRE_CLICK_WAIT_MS = 500
MIN_ROUTINE_CYCLE_DELAY_MS = 200
DEFAULT_ROUTINE_CYCLE_DELAY_MS = 300
MIN_POST_CLICK_DELAY_MS = 500
DEFAULT_POST_CLICK_DELAY_MS = 700
DEFAULT_MAX_CYCLES = 50
MAX_PRE_POINT_WARNING_COUNT = 10


def rgb_to_hex(rgb: tuple[int, int, int]) -> str:
    return "#{:02X}{:02X}{:02X}".format(*rgb)


def clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, value))


def normalize_region(
    x1: int,
    y1: int,
    x2: int,
    y2: int,
    min_size: int = 4,
) -> tuple[int, int, int, int] | None:
    left = min(x1, x2)
    top = min(y1, y2)
    width = abs(x2 - x1)
    height = abs(y2 - y1)
    if width < min_size or height < min_size:
        return None
    return left, top, width, height


def format_region(region: tuple[int, int, int, int] | None) -> str:
    if region is None:
        return "전체 화면 캡처"
    left, top, width, height = region
    return f"캡처 영역 x={left}, y={top}, w={width}, h={height}"


Coordinate = tuple[int, int]
RoutinePoint = tuple[int, int, int]


def capture_to_ppm_preview(
    data: bytes,
    width: int,
    height: int,
    max_width: int,
    max_height: int,
) -> tuple[bytes, int, int]:
    scale = min(max_width / width, max_height / height)
    preview_width = max(1, int(width * scale))
    preview_height = max(1, int(height * scale))

    header = f"P6\n{preview_width} {preview_height}\n255\n".encode("ascii")
    pixels = bytearray(preview_width * preview_height * 3)
    write_offset = 0
    row_stride = width * 4

    for preview_y in range(preview_height):
        source_y = min(height - 1, (preview_y * height) // preview_height)
        row_offset = source_y * row_stride
        for preview_x in range(preview_width):
            source_x = min(width - 1, (preview_x * width) // preview_width)
            source_offset = row_offset + (source_x * 4)
            pixels[write_offset] = data[source_offset + 2]
            pixels[write_offset + 1] = data[source_offset + 1]
            pixels[write_offset + 2] = data[source_offset]
            write_offset += 3

    return header + bytes(pixels), preview_width, preview_height


class BitmapInfoHeader(ctypes.Structure):
    _fields_ = [
        ("biSize", wintypes.DWORD),
        ("biWidth", wintypes.LONG),
        ("biHeight", wintypes.LONG),
        ("biPlanes", wintypes.WORD),
        ("biBitCount", wintypes.WORD),
        ("biCompression", wintypes.DWORD),
        ("biSizeImage", wintypes.DWORD),
        ("biXPelsPerMeter", wintypes.LONG),
        ("biYPelsPerMeter", wintypes.LONG),
        ("biClrUsed", wintypes.DWORD),
        ("biClrImportant", wintypes.DWORD),
    ]


class RgbQuad(ctypes.Structure):
    _fields_ = [
        ("rgbBlue", ctypes.c_ubyte),
        ("rgbGreen", ctypes.c_ubyte),
        ("rgbRed", ctypes.c_ubyte),
        ("rgbReserved", ctypes.c_ubyte),
    ]


class BitmapInfo(ctypes.Structure):
    _fields_ = [
        ("bmiHeader", BitmapInfoHeader),
        ("bmiColors", RgbQuad * 1),
    ]


class WindowsScreen:
    """Small Windows API wrapper for screen pixels and cursor movement."""

    SRCCOPY = 0x00CC0020
    DIB_RGB_COLORS = 0
    BI_RGB = 0

    SM_XVIRTUALSCREEN = 76
    SM_YVIRTUALSCREEN = 77
    SM_CXVIRTUALSCREEN = 78
    SM_CYVIRTUALSCREEN = 79
    VK_LBUTTON = 0x01
    VK_RBUTTON = 0x02
    VK_ESCAPE = 0x1B
    MOUSEEVENTF_LEFTDOWN = 0x0002
    MOUSEEVENTF_LEFTUP = 0x0004

    def __init__(self) -> None:
        if os.name != "nt":
            raise RuntimeError("이 예제 프로그램은 Windows 화면 캡처 API를 사용합니다.")

        self.user32 = ctypes.WinDLL("user32", use_last_error=True)
        self.gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
        self._configure_signatures()

        try:
            self.user32.SetProcessDPIAware()
        except Exception:
            pass

    def _configure_signatures(self) -> None:
        self.user32.GetSystemMetrics.argtypes = [ctypes.c_int]
        self.user32.GetSystemMetrics.restype = ctypes.c_int
        self.user32.GetCursorPos.argtypes = [ctypes.POINTER(wintypes.POINT)]
        self.user32.GetCursorPos.restype = wintypes.BOOL
        self.user32.SetCursorPos.argtypes = [ctypes.c_int, ctypes.c_int]
        self.user32.SetCursorPos.restype = wintypes.BOOL
        self.user32.GetAsyncKeyState.argtypes = [ctypes.c_int]
        self.user32.GetAsyncKeyState.restype = ctypes.c_short
        self.user32.mouse_event.argtypes = [
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
        ]
        self.user32.mouse_event.restype = None
        self.user32.GetDC.argtypes = [wintypes.HWND]
        self.user32.GetDC.restype = wintypes.HDC
        self.user32.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
        self.user32.ReleaseDC.restype = ctypes.c_int

        self.gdi32.GetPixel.argtypes = [wintypes.HDC, ctypes.c_int, ctypes.c_int]
        self.gdi32.GetPixel.restype = ctypes.c_uint32
        self.gdi32.CreateCompatibleDC.argtypes = [wintypes.HDC]
        self.gdi32.CreateCompatibleDC.restype = wintypes.HDC
        self.gdi32.CreateCompatibleBitmap.argtypes = [
            wintypes.HDC,
            ctypes.c_int,
            ctypes.c_int,
        ]
        self.gdi32.CreateCompatibleBitmap.restype = wintypes.HBITMAP
        self.gdi32.SelectObject.argtypes = [wintypes.HDC, wintypes.HGDIOBJ]
        self.gdi32.SelectObject.restype = wintypes.HANDLE
        self.gdi32.BitBlt.argtypes = [
            wintypes.HDC,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            wintypes.HDC,
            ctypes.c_int,
            ctypes.c_int,
            wintypes.DWORD,
        ]
        self.gdi32.BitBlt.restype = wintypes.BOOL
        self.gdi32.GetDIBits.argtypes = [
            wintypes.HDC,
            wintypes.HBITMAP,
            wintypes.UINT,
            wintypes.UINT,
            wintypes.LPVOID,
            ctypes.POINTER(BitmapInfo),
            wintypes.UINT,
        ]
        self.gdi32.GetDIBits.restype = ctypes.c_int
        self.gdi32.DeleteObject.argtypes = [wintypes.HGDIOBJ]
        self.gdi32.DeleteObject.restype = wintypes.BOOL
        self.gdi32.DeleteDC.argtypes = [wintypes.HDC]
        self.gdi32.DeleteDC.restype = wintypes.BOOL

    def virtual_bounds(self) -> tuple[int, int, int, int]:
        left = self.user32.GetSystemMetrics(self.SM_XVIRTUALSCREEN)
        top = self.user32.GetSystemMetrics(self.SM_YVIRTUALSCREEN)
        width = self.user32.GetSystemMetrics(self.SM_CXVIRTUALSCREEN)
        height = self.user32.GetSystemMetrics(self.SM_CYVIRTUALSCREEN)
        return left, top, width, height

    def cursor_position(self) -> tuple[int, int]:
        point = wintypes.POINT()
        if not self.user32.GetCursorPos(ctypes.byref(point)):
            raise OSError(ctypes.get_last_error(), "GetCursorPos failed")
        return point.x, point.y

    def pixel_at(self, x: int, y: int) -> tuple[int, int, int]:
        screen_dc = self.user32.GetDC(None)
        if not screen_dc:
            raise OSError(ctypes.get_last_error(), "GetDC failed")
        try:
            color = self.gdi32.GetPixel(screen_dc, x, y)
            if color == 0xFFFFFFFF:
                raise OSError(ctypes.get_last_error(), "GetPixel failed")
            red = color & 0xFF
            green = (color >> 8) & 0xFF
            blue = (color >> 16) & 0xFF
            return red, green, blue
        finally:
            self.user32.ReleaseDC(None, screen_dc)

    def move_mouse(self, x: int, y: int) -> None:
        if not self.user32.SetCursorPos(int(x), int(y)):
            raise OSError(ctypes.get_last_error(), "SetCursorPos failed")

    def click_left(self, x: int, y: int, press_ms: int = 35) -> None:
        self.move_mouse(x, y)
        time.sleep(0.02)
        self.user32.mouse_event(self.MOUSEEVENTF_LEFTDOWN, 0, 0, 0, None)
        time.sleep(max(0.005, press_ms / 1000))
        self.user32.mouse_event(self.MOUSEEVENTF_LEFTUP, 0, 0, 0, None)

    def left_button_down(self) -> bool:
        return bool(self.user32.GetAsyncKeyState(self.VK_LBUTTON) & 0x8000)

    def right_button_down(self) -> bool:
        return bool(self.user32.GetAsyncKeyState(self.VK_RBUTTON) & 0x8000)

    def escape_down(self) -> bool:
        return bool(self.user32.GetAsyncKeyState(self.VK_ESCAPE) & 0x8000)

    def capture_screen(self) -> tuple[bytes, int, int, int, int]:
        left, top, width, height = self.virtual_bounds()
        return self.capture_region(left, top, width, height)

    def capture_region(
        self, left: int, top: int, width: int, height: int
    ) -> tuple[bytes, int, int, int, int]:
        left = int(left)
        top = int(top)
        width = int(width)
        height = int(height)
        if width <= 0 or height <= 0:
            raise ValueError("캡처 영역의 너비와 높이는 1 이상이어야 합니다.")

        screen_dc = self.user32.GetDC(None)
        if not screen_dc:
            raise OSError(ctypes.get_last_error(), "GetDC failed")

        mem_dc = self.gdi32.CreateCompatibleDC(screen_dc)
        if not mem_dc:
            self.user32.ReleaseDC(None, screen_dc)
            raise OSError(ctypes.get_last_error(), "CreateCompatibleDC failed")

        bitmap = self.gdi32.CreateCompatibleBitmap(screen_dc, width, height)
        if not bitmap:
            self.gdi32.DeleteDC(mem_dc)
            self.user32.ReleaseDC(None, screen_dc)
            raise OSError(ctypes.get_last_error(), "CreateCompatibleBitmap failed")

        old_object = self.gdi32.SelectObject(mem_dc, bitmap)
        try:
            if not self.gdi32.BitBlt(
                mem_dc,
                0,
                0,
                width,
                height,
                screen_dc,
                left,
                top,
                self.SRCCOPY,
            ):
                raise OSError(ctypes.get_last_error(), "BitBlt failed")

            bmi = BitmapInfo()
            bmi.bmiHeader.biSize = ctypes.sizeof(BitmapInfoHeader)
            bmi.bmiHeader.biWidth = width
            bmi.bmiHeader.biHeight = -height
            bmi.bmiHeader.biPlanes = 1
            bmi.bmiHeader.biBitCount = 32
            bmi.bmiHeader.biCompression = self.BI_RGB
            bmi.bmiHeader.biSizeImage = width * height * 4

            buffer = ctypes.create_string_buffer(width * height * 4)
            lines = self.gdi32.GetDIBits(
                mem_dc,
                bitmap,
                0,
                height,
                buffer,
                ctypes.byref(bmi),
                self.DIB_RGB_COLORS,
            )
            if lines == 0:
                raise OSError(ctypes.get_last_error(), "GetDIBits failed")

            return buffer.raw, left, top, width, height
        finally:
            if old_object:
                self.gdi32.SelectObject(mem_dc, old_object)
            self.gdi32.DeleteObject(bitmap)
            self.gdi32.DeleteDC(mem_dc)
            self.user32.ReleaseDC(None, screen_dc)


def find_matching_pixel(
    data: bytes,
    width: int,
    height: int,
    left: int,
    top: int,
    target: tuple[int, int, int],
    tolerance: int,
    step: int,
) -> tuple[int, int, tuple[int, int, int]] | None:
    target_red, target_green, target_blue = target
    row_stride = width * 4

    for y in range(0, height, step):
        row_offset = y * row_stride
        for x in range(0, width, step):
            offset = row_offset + (x * 4)
            blue = data[offset]
            green = data[offset + 1]
            red = data[offset + 2]

            if (
                abs(red - target_red) <= tolerance
                and abs(green - target_green) <= tolerance
                and abs(blue - target_blue) <= tolerance
            ):
                return left + x, top + y, (red, green, blue)

    return None


class EyedropperOverlay:
    """Full-screen picker overlay with a cursor-side color preview."""

    TRANSPARENT_COLOR = "#FF00FF"
    PANEL_WIDTH = 178
    PANEL_HEIGHT = 58

    def __init__(
        self,
        root: tk.Tk,
        screen: WindowsScreen,
        on_pick: Callable[[tuple[int, int, int], int, int], None],
        on_cancel: Callable[[], None],
        on_error: Callable[[Exception], None],
    ) -> None:
        self.root = root
        self.screen = screen
        self.on_pick = on_pick
        self.on_cancel = on_cancel
        self.on_error = on_error
        self.left, self.top, self.width, self.height = screen.virtual_bounds()
        self.closed = False
        self.waiting_for_release = screen.left_button_down()
        self.current_rgb = (0, 0, 0)
        self.current_pos = (self.left, self.top)
        self.grabbed = False

        self.window = tk.Toplevel(root)
        self.window.withdraw()
        self.window.overrideredirect(True)
        self.window.configure(bg=self.TRANSPARENT_COLOR, cursor="none")
        self.window.geometry(
            f"{self.width}x{self.height}{self.left:+d}{self.top:+d}"
        )
        self.window.attributes("-topmost", True)
        try:
            self.window.attributes("-transparentcolor", self.TRANSPARENT_COLOR)
        except tk.TclError:
            self.window.attributes("-alpha", 0.12)

        self.canvas = tk.Canvas(
            self.window,
            bg=self.TRANSPARENT_COLOR,
            bd=0,
            highlightthickness=0,
            cursor="none",
        )
        self.canvas.pack(fill=tk.BOTH, expand=True)

        self.window.bind("<Escape>", self._cancel_from_event)
        self.window.bind("<Button-1>", self._pick_from_event)
        self.window.bind("<Button-3>", self._cancel_from_event)
        self.window.deiconify()
        self.window.lift()
        self.window.focus_force()
        try:
            self.window.grab_set_global()
            self.grabbed = True
        except tk.TclError:
            self.grabbed = False

        self._poll()

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self.grabbed:
            try:
                self.window.grab_release()
            except tk.TclError:
                pass
        self.window.destroy()

    def _cancel_from_event(self, _event: tk.Event | None = None) -> None:
        if self.closed:
            return
        self.close()
        self.on_cancel()

    def _pick_from_event(self, _event: tk.Event | None = None) -> None:
        if self.closed or self.waiting_for_release:
            return
        x, y = self.current_pos
        rgb = self.current_rgb
        self.close()
        self.on_pick(rgb, x, y)

    def _poll(self) -> None:
        if self.closed:
            return

        try:
            x, y = self.screen.cursor_position()
            rgb = self.screen.pixel_at(x, y)
        except OSError as exc:
            self.close()
            self.on_error(exc)
            return

        self.current_pos = (x, y)
        self.current_rgb = rgb
        self._draw_pointer(x, y, rgb)

        left_down = self.screen.left_button_down()
        if self.waiting_for_release:
            self.waiting_for_release = left_down
        elif left_down:
            self._pick_from_event()
            return

        if self.screen.right_button_down() or self.screen.escape_down():
            self._cancel_from_event()
            return

        self.root.after(25, self._poll)

    def _draw_pointer(
        self, screen_x: int, screen_y: int, rgb: tuple[int, int, int]
    ) -> None:
        x = screen_x - self.left
        y = screen_y - self.top
        self.canvas.delete("eyedropper")

        side = -1 if x + 230 > self.width else 1
        vertical = -1 if y + 105 > self.height else 1
        panel_x = x + 42 if side > 0 else x - self.PANEL_WIDTH - 42
        panel_y = y + 22 if vertical > 0 else y - self.PANEL_HEIGHT - 22
        panel_x = clamp(panel_x, 8, max(8, self.width - self.PANEL_WIDTH - 8))
        panel_y = clamp(panel_y, 8, max(8, self.height - self.PANEL_HEIGHT - 8))
        color_hex = rgb_to_hex(rgb)

        self._draw_hotspot(x, y)
        self._draw_dropper(x, y, side, vertical)
        self._draw_preview_panel(panel_x, panel_y, rgb, color_hex)

    def _draw_hotspot(self, x: int, y: int) -> None:
        self.canvas.create_oval(
            x - 8,
            y - 8,
            x + 8,
            y + 8,
            outline="#101010",
            width=3,
            tags="eyedropper",
        )
        self.canvas.create_oval(
            x - 6,
            y - 6,
            x + 6,
            y + 6,
            outline="#FFFFFF",
            width=1,
            tags="eyedropper",
        )
        for start, end in (
            ((x - 16, y), (x - 10, y)),
            ((x + 10, y), (x + 16, y)),
            ((x, y - 16), (x, y - 10)),
            ((x, y + 10), (x, y + 16)),
        ):
            self.canvas.create_line(
                *start,
                *end,
                fill="#FFFFFF",
                width=3,
                tags="eyedropper",
            )
            self.canvas.create_line(
                *start,
                *end,
                fill="#101010",
                width=1,
                tags="eyedropper",
            )

    def _draw_dropper(self, x: int, y: int, side: int, vertical: int) -> None:
        start_x = x + (side * 12)
        start_y = y + (vertical * 12)
        end_x = x + (side * 34)
        end_y = y + (vertical * 34)
        bulb_x = x + (side * 44)
        bulb_y = y + (vertical * 44)

        self.canvas.create_line(
            start_x,
            start_y,
            end_x,
            end_y,
            fill="#111111",
            width=9,
            capstyle=tk.ROUND,
            tags="eyedropper",
        )
        self.canvas.create_line(
            start_x,
            start_y,
            end_x,
            end_y,
            fill="#F4F7FA",
            width=6,
            capstyle=tk.ROUND,
            tags="eyedropper",
        )
        self.canvas.create_line(
            start_x,
            start_y,
            end_x,
            end_y,
            fill="#4A8FE7",
            width=2,
            capstyle=tk.ROUND,
            tags="eyedropper",
        )
        self.canvas.create_oval(
            bulb_x - 8,
            bulb_y - 8,
            bulb_x + 8,
            bulb_y + 8,
            fill="#F4F7FA",
            outline="#111111",
            width=2,
            tags="eyedropper",
        )
        self.canvas.create_oval(
            bulb_x - 4,
            bulb_y - 4,
            bulb_x + 4,
            bulb_y + 4,
            fill="#4A8FE7",
            outline="",
            tags="eyedropper",
        )

    def _draw_preview_panel(
        self,
        x: int,
        y: int,
        rgb: tuple[int, int, int],
        color_hex: str,
    ) -> None:
        self.canvas.create_rectangle(
            x + 2,
            y + 2,
            x + self.PANEL_WIDTH + 2,
            y + self.PANEL_HEIGHT + 2,
            fill="#000000",
            outline="",
            stipple="gray50",
            tags="eyedropper",
        )
        self.canvas.create_rectangle(
            x,
            y,
            x + self.PANEL_WIDTH,
            y + self.PANEL_HEIGHT,
            fill="#FFFFFF",
            outline="#111111",
            width=1,
            tags="eyedropper",
        )
        self.canvas.create_rectangle(
            x + 10,
            y + 10,
            x + 48,
            y + 48,
            fill=color_hex,
            outline="#111111",
            width=1,
            tags="eyedropper",
        )
        self.canvas.create_text(
            x + 60,
            y + 17,
            text=f"RGB {rgb[0]}, {rgb[1]}, {rgb[2]}",
            anchor="w",
            fill="#111111",
            font=("Consolas", 10, "bold"),
            tags="eyedropper",
        )
        self.canvas.create_text(
            x + 60,
            y + 38,
            text=color_hex,
            anchor="w",
            fill="#333333",
            font=("Consolas", 10),
            tags="eyedropper",
        )


class PointPickerOverlay:
    """Full-screen click overlay for recording one coordinate."""

    def __init__(
        self,
        root: tk.Tk,
        screen: WindowsScreen,
        label: str,
        on_pick: Callable[[int, int], None],
        on_cancel: Callable[[], None],
    ) -> None:
        self.root = root
        self.screen = screen
        self.label = label
        self.on_pick = on_pick
        self.on_cancel = on_cancel
        self.left, self.top, self.width, self.height = screen.virtual_bounds()
        self.closed = False
        self.grabbed = False
        self.waiting_for_release = screen.left_button_down()

        self.window = tk.Toplevel(root)
        self.window.withdraw()
        self.window.overrideredirect(True)
        self.window.configure(bg="#101010", cursor="crosshair")
        self.window.geometry(
            f"{self.width}x{self.height}{self.left:+d}{self.top:+d}"
        )
        self.window.attributes("-topmost", True)
        self.window.attributes("-alpha", 0.20)

        self.canvas = tk.Canvas(
            self.window,
            bg="#101010",
            bd=0,
            highlightthickness=0,
            cursor="crosshair",
        )
        self.canvas.pack(fill=tk.BOTH, expand=True)
        self.canvas.create_text(
            self.width // 2,
            36,
            text=f"{label}: 저장할 위치를 클릭하세요. Esc 또는 오른쪽 클릭으로 취소",
            fill="#FFFFFF",
            font=("Malgun Gothic", 14, "bold"),
            tags="guide",
        )

        self.window.bind("<Escape>", self._cancel_from_event)
        self.window.bind("<Button-1>", self._pick_from_event)
        self.window.bind("<Motion>", self._draw_cursor)
        self.window.bind("<Button-3>", self._cancel_from_event)
        self.window.deiconify()
        self.window.lift()
        self.window.focus_force()
        try:
            self.window.grab_set_global()
            self.grabbed = True
        except tk.TclError:
            self.grabbed = False
        self._poll_keys()

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self.grabbed:
            try:
                self.window.grab_release()
            except tk.TclError:
                pass
        self.window.destroy()

    def _cancel_from_event(self, _event: tk.Event | None = None) -> None:
        if self.closed:
            return
        self.close()
        self.on_cancel()

    def _pick_from_event(self, event: tk.Event) -> None:
        if self.closed or self.waiting_for_release:
            return
        x = self.left + int(event.x)
        y = self.top + int(event.y)
        self.close()
        self.on_pick(x, y)

    def _poll_keys(self) -> None:
        if self.closed:
            return
        left_down = self.screen.left_button_down()
        if self.waiting_for_release:
            self.waiting_for_release = left_down
        if self.screen.right_button_down() or self.screen.escape_down():
            self._cancel_from_event()
            return
        self.root.after(25, self._poll_keys)

    def _draw_cursor(self, event: tk.Event) -> None:
        self.canvas.delete("cursor")
        x = int(event.x)
        y = int(event.y)
        self.canvas.create_line(
            x - 14, y, x + 14, y, fill="#FFFFFF", width=2, tags="cursor"
        )
        self.canvas.create_line(
            x, y - 14, x, y + 14, fill="#FFFFFF", width=2, tags="cursor"
        )
        self.canvas.create_oval(
            x - 5,
            y - 5,
            x + 5,
            y + 5,
            outline="#4AA3FF",
            width=2,
            tags="cursor",
        )
        self.canvas.create_rectangle(
            x + 16,
            y + 16,
            x + 160,
            y + 44,
            fill="#FFFFFF",
            outline="#111111",
            tags="cursor",
        )
        self.canvas.create_text(
            x + 24,
            y + 30,
            text=f"x={self.left + x}, y={self.top + y}",
            anchor="w",
            fill="#111111",
            font=("Consolas", 10, "bold"),
            tags="cursor",
        )


class RegionSelectorOverlay:
    """Full-screen drag overlay for choosing the scan region."""

    def __init__(
        self,
        root: tk.Tk,
        screen: WindowsScreen,
        on_select: Callable[[tuple[int, int, int, int]], None],
        on_cancel: Callable[[], None],
    ) -> None:
        self.root = root
        self.screen = screen
        self.on_select = on_select
        self.on_cancel = on_cancel
        self.left, self.top, self.width, self.height = screen.virtual_bounds()
        self.start: tuple[int, int] | None = None
        self.closed = False
        self.grabbed = False

        self.window = tk.Toplevel(root)
        self.window.withdraw()
        self.window.overrideredirect(True)
        self.window.configure(bg="#111111", cursor="crosshair")
        self.window.geometry(
            f"{self.width}x{self.height}{self.left:+d}{self.top:+d}"
        )
        self.window.attributes("-topmost", True)
        self.window.attributes("-alpha", 0.26)

        self.canvas = tk.Canvas(
            self.window,
            bg="#111111",
            bd=0,
            highlightthickness=0,
            cursor="crosshair",
        )
        self.canvas.pack(fill=tk.BOTH, expand=True)
        self.canvas.create_text(
            self.width // 2,
            36,
            text="드래그해서 탐지할 영역을 지정하세요. Esc 또는 오른쪽 클릭으로 취소",
            fill="#FFFFFF",
            font=("Malgun Gothic", 14, "bold"),
            tags="guide",
        )

        self.window.bind("<Escape>", self._cancel_from_event)
        self.window.bind("<Button-1>", self._start_drag)
        self.window.bind("<B1-Motion>", self._update_drag)
        self.window.bind("<ButtonRelease-1>", self._finish_drag)
        self.window.bind("<Button-3>", self._cancel_from_event)
        self.window.deiconify()
        self.window.lift()
        self.window.focus_force()
        try:
            self.window.grab_set_global()
            self.grabbed = True
        except tk.TclError:
            self.grabbed = False

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self.grabbed:
            try:
                self.window.grab_release()
            except tk.TclError:
                pass
        self.window.destroy()

    def _cancel_from_event(self, _event: tk.Event | None = None) -> None:
        if self.closed:
            return
        self.close()
        self.on_cancel()

    def _start_drag(self, event: tk.Event) -> None:
        self.start = (event.x, event.y)
        self._draw_selection(event.x, event.y)

    def _update_drag(self, event: tk.Event) -> None:
        if self.start is None:
            return
        self._draw_selection(event.x, event.y)

    def _finish_drag(self, event: tk.Event) -> None:
        if self.closed or self.start is None:
            return

        start_x, start_y = self.start
        region = normalize_region(
            self.left + start_x,
            self.top + start_y,
            self.left + event.x,
            self.top + event.y,
        )
        if region is None:
            self.canvas.delete("selection")
            self.canvas.create_text(
                self.width // 2,
                72,
                text="영역이 너무 작습니다. 다시 드래그하세요.",
                fill="#FFD4D4",
                font=("Malgun Gothic", 12, "bold"),
                tags="selection",
            )
            self.start = None
            return

        self.close()
        self.on_select(region)

    def _draw_selection(self, current_x: int, current_y: int) -> None:
        if self.start is None:
            return

        start_x, start_y = self.start
        left = min(start_x, current_x)
        top = min(start_y, current_y)
        right = max(start_x, current_x)
        bottom = max(start_y, current_y)
        width = max(0, right - left)
        height = max(0, bottom - top)
        screen_left = self.left + left
        screen_top = self.top + top

        self.canvas.delete("selection")
        self.canvas.create_rectangle(
            left,
            top,
            right,
            bottom,
            fill="#4AA3FF",
            outline="#FFFFFF",
            width=2,
            stipple="gray25",
            tags="selection",
        )
        self.canvas.create_rectangle(
            left + 2,
            top + 2,
            right - 2,
            bottom - 2,
            outline="#4AA3FF",
            width=2,
            tags="selection",
        )

        label = f"x={screen_left}, y={screen_top}, w={width}, h={height}"
        label_x = clamp(left, 12, max(12, self.width - 260))
        label_y = top - 30 if top > 42 else bottom + 14
        label_y = clamp(label_y, 12, max(12, self.height - 34))
        self.canvas.create_rectangle(
            label_x - 8,
            label_y - 6,
            label_x + 250,
            label_y + 24,
            fill="#FFFFFF",
            outline="#111111",
            tags="selection",
        )
        self.canvas.create_text(
            label_x,
            label_y + 9,
            text=label,
            anchor="w",
            fill="#111111",
            font=("Consolas", 10, "bold"),
            tags="selection",
        )


class LocalPixelMouseAssistantApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1120x940")
        self.root.minsize(980, 860)

        self.screen = WindowsScreen()
        self.target_color: tuple[int, int, int] = (0, 128, 255)
        self.scan_thread: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.eyedropper_active = False
        self.eyedropper_overlay: EyedropperOverlay | None = None
        self.region_overlay: RegionSelectorOverlay | None = None
        self.point_picker_overlay: PointPickerOverlay | None = None
        self.scan_region: tuple[int, int, int, int] | None = None
        self.capture_preview_image: tk.PhotoImage | None = None
        self.preview_after_id: str | None = None
        self.pre_routine_points: list[RoutinePoint] = []
        self.post_routine_points: list[Coordinate] = []
        self.pending_point_kind: str | None = None
        self.point_input_close: Callable[[], None] | None = None
        self.color_before_eyedropper = self.target_color
        self.last_finish_message = "탐지가 정지되었습니다."

        self.red_var = tk.StringVar(value="0")
        self.green_var = tk.StringVar(value="128")
        self.blue_var = tk.StringVar(value="255")
        self.hex_var = tk.StringVar(value=rgb_to_hex(self.target_color))
        self.tolerance_var = tk.IntVar(value=18)
        self.step_var = tk.IntVar(value=4)
        self.interval_var = tk.IntVar(value=DEFAULT_SCAN_INTERVAL_MS)
        self.stop_on_first_var = tk.BooleanVar(value=True)
        self.status_var = tk.StringVar(value="대기 중입니다. 대상 색상과 탐지 캡처 영역을 확인하세요.")
        self.tolerance_label_var = tk.StringVar()
        self.region_var = tk.StringVar(value=format_region(self.scan_region))
        self.live_preview_var = tk.BooleanVar(value=True)
        self.preview_status_var = tk.StringVar(value="탐지 캡처 프리뷰 준비 중입니다.")
        self.routine_click_delay_var = tk.IntVar(value=DEFAULT_PRE_CLICK_WAIT_MS)
        self.routine_cycle_delay_var = tk.IntVar(value=DEFAULT_ROUTINE_CYCLE_DELAY_MS)
        self.post_click_delay_var = tk.IntVar(value=DEFAULT_POST_CLICK_DELAY_MS)
        self.max_cycles_var = tk.IntVar(value=DEFAULT_MAX_CYCLES)
        self.auto_click_on_match_var = tk.BooleanVar(value=False)
        self.auto_click_safety_ack_var = tk.BooleanVar(value=False)
        self.run_post_points_var = tk.BooleanVar(value=False)
        self.confirm_selection_var = tk.BooleanVar(value=True)
        self.confirm_wait_var = tk.IntVar(value=900)

        self._build_ui()
        self._update_target_display()
        self._update_tolerance_label()
        self.root.after(350, self.update_capture_preview_once)
        self.root.after(700, self._schedule_capture_preview)
        self.root.after(250, self._show_notice)
        self.root.protocol("WM_DELETE_WINDOW", self._close)

    def _build_ui(self) -> None:
        try:
            ttk.Style().theme_use("clam")
        except tk.TclError:
            pass

        content = ttk.Frame(self.root)
        content.pack(fill=tk.BOTH, expand=True)
        content.columnconfigure(0, weight=3)
        content.columnconfigure(1, weight=2)
        content.rowconfigure(0, weight=1)

        outer = ttk.Frame(content, padding=16)
        outer.grid(row=0, column=0, sticky="nsew")
        routine_pane = ttk.Frame(content, padding=(0, 16, 16, 16))
        routine_pane.grid(row=0, column=1, sticky="nsew")

        notice = tk.Label(
            outer,
            text=NOTICE_TEXT,
            justify=tk.CENTER,
            fg="#8A0000",
            bg="#FFF0F0",
            bd=1,
            relief=tk.SOLID,
            padx=12,
            pady=10,
            font=("Malgun Gothic", 11, "bold"),
        )
        notice.pack(fill=tk.X)

        color_frame = ttk.LabelFrame(outer, text="찾을 대상 색상", padding=12)
        color_frame.pack(fill=tk.X, pady=(14, 10))
        color_frame.columnconfigure(1, weight=1)

        self.preview = tk.Canvas(
            color_frame,
            width=72,
            height=44,
            bd=1,
            highlightthickness=1,
            highlightbackground="#8E8E8E",
        )
        self.preview.grid(row=0, column=0, rowspan=3, sticky="n", padx=(0, 12))
        self.preview_rect = self.preview.create_rectangle(0, 0, 74, 46, outline="")

        ttk.Label(color_frame, text="HEX").grid(row=0, column=1, sticky="w")
        ttk.Label(color_frame, textvariable=self.hex_var, font=("Consolas", 11)).grid(
            row=0, column=2, sticky="w", padx=(8, 0)
        )

        rgb_frame = ttk.Frame(color_frame)
        rgb_frame.grid(row=1, column=1, columnspan=3, sticky="ew", pady=(8, 0))
        for index, (label, variable) in enumerate(
            (("R", self.red_var), ("G", self.green_var), ("B", self.blue_var))
        ):
            ttk.Label(rgb_frame, text=label).grid(row=0, column=index * 2, sticky="w")
            spinbox = self._spinbox(rgb_frame, variable, 0, 255, width=5)
            spinbox.grid(row=0, column=index * 2 + 1, sticky="w", padx=(4, 10))

        button_frame = ttk.Frame(color_frame)
        button_frame.grid(row=2, column=1, columnspan=3, sticky="ew", pady=(10, 0))
        ttk.Button(button_frame, text="RGB 적용", command=self.apply_rgb).pack(
            side=tk.LEFT
        )
        ttk.Button(button_frame, text="대상 색상 선택", command=self.choose_color).pack(
            side=tk.LEFT, padx=(8, 0)
        )
        self.eyedropper_button = ttk.Button(
            button_frame, text="스포이드 시작", command=self.toggle_eyedropper
        )
        self.eyedropper_button.pack(side=tk.LEFT, padx=(8, 0))

        scan_frame = ttk.LabelFrame(outer, text="탐지 설정", padding=12)
        scan_frame.pack(fill=tk.X, pady=(0, 10))
        scan_frame.columnconfigure(1, weight=1)

        ttk.Label(scan_frame, textvariable=self.tolerance_label_var).grid(
            row=0, column=0, columnspan=2, sticky="w"
        )
        tolerance = ttk.Scale(
            scan_frame,
            from_=0,
            to=80,
            orient=tk.HORIZONTAL,
            variable=self.tolerance_var,
            command=lambda _value: self._update_tolerance_label(),
        )
        tolerance.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(4, 10))

        ttk.Label(scan_frame, text="스캔 간격(ms)").grid(row=2, column=0, sticky="w")
        self._spinbox(scan_frame, self.interval_var, MIN_SCAN_INTERVAL_MS, 2000, width=8).grid(
            row=2, column=1, sticky="w", padx=(10, 0)
        )

        ttk.Label(scan_frame, text="스캔 촘촘함(px)").grid(
            row=3, column=0, sticky="w", pady=(8, 0)
        )
        self._spinbox(scan_frame, self.step_var, 1, 20, width=8).grid(
            row=3, column=1, sticky="w", padx=(10, 0), pady=(8, 0)
        )

        ttk.Checkbutton(
            scan_frame,
            text="첫 탐지 후 자동 정지",
            variable=self.stop_on_first_var,
        ).grid(row=4, column=0, columnspan=2, sticky="w", pady=(10, 0))

        region_frame = ttk.LabelFrame(outer, text="색상 탐지 캡처 영역", padding=12)
        region_frame.pack(fill=tk.X, pady=(0, 10))
        region_frame.columnconfigure(1, weight=1)

        ttk.Label(region_frame, text="현재 탐지 범위").grid(row=0, column=0, sticky="w")
        ttk.Label(
            region_frame,
            textvariable=self.region_var,
            font=("Consolas", 10),
        ).grid(row=0, column=1, sticky="w", padx=(10, 0))

        region_buttons = ttk.Frame(region_frame)
        region_buttons.grid(row=1, column=0, columnspan=2, sticky="w", pady=(10, 0))
        self.region_button = ttk.Button(
            region_buttons,
            text="드래그로 탐지 영역 지정",
            command=self.start_region_selection,
        )
        self.region_button.pack(side=tk.LEFT)
        ttk.Button(
            region_buttons,
            text="전체 화면 탐지",
            command=self.clear_scan_region,
        ).pack(side=tk.LEFT, padx=(8, 0))

        preview_frame = ttk.LabelFrame(outer, text="탐지 캡처 프리뷰", padding=12)
        preview_frame.pack(fill=tk.X, pady=(0, 10))
        preview_frame.columnconfigure(0, weight=1)

        self.capture_preview_canvas = tk.Canvas(
            preview_frame,
            width=580,
            height=190,
            bg="#141414",
            bd=0,
            highlightthickness=1,
            highlightbackground="#8E8E8E",
        )
        self.capture_preview_canvas.grid(row=0, column=0, columnspan=3, sticky="ew")
        self.capture_preview_canvas.create_text(
            290,
            95,
            text="탐지 캡처 프리뷰 준비 중",
            fill="#FFFFFF",
            font=("Malgun Gothic", 12, "bold"),
            tags="placeholder",
        )

        ttk.Label(
            preview_frame,
            textvariable=self.preview_status_var,
            font=("Malgun Gothic", 9),
        ).grid(row=1, column=0, sticky="w", pady=(8, 0))

        ttk.Checkbutton(
            preview_frame,
            text="실시간 탐지 캡처",
            variable=self.live_preview_var,
            command=self._toggle_live_preview,
        ).grid(row=1, column=1, sticky="e", padx=(8, 0), pady=(8, 0))
        ttk.Button(
            preview_frame,
            text="탐지 캡처 갱신",
            command=self.update_capture_preview_once,
        ).grid(row=1, column=2, sticky="e", padx=(8, 0), pady=(8, 0))

        control_frame = ttk.Frame(outer)
        control_frame.pack(fill=tk.X, pady=(4, 10))
        self.start_button = ttk.Button(
            control_frame, text="탐지 시작", command=self.start_scan
        )
        self.start_button.pack(side=tk.LEFT)
        self.stop_button = ttk.Button(
            control_frame, text="정지", command=self.stop_scan, state=tk.DISABLED
        )
        self.stop_button.pack(side=tk.LEFT, padx=(8, 0))

        status_frame = ttk.LabelFrame(outer, text="상태", padding=12)
        status_frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(
            status_frame,
            textvariable=self.status_var,
            wraplength=560,
            justify=tk.LEFT,
        ).pack(fill=tk.BOTH, expand=True, anchor="nw")

        self._build_routine_ui(routine_pane)

    def _spinbox(
        self,
        parent: tk.Widget,
        variable: tk.Variable,
        from_: int,
        to: int,
        width: int,
    ) -> tk.Widget:
        spinbox_class = getattr(ttk, "Spinbox", tk.Spinbox)
        return spinbox_class(
            parent,
            from_=from_,
            to=to,
            width=width,
            textvariable=variable,
            justify=tk.CENTER,
        )

    def _build_routine_ui(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(0, weight=1)

        warning = tk.Label(
            parent,
            text=(
                "안전 주의: 최종 결제/약관 동의/구매 확정/주문 제출 좌표는 절대 넣지 마세요.\n"
                "재판매, 대리예매, 다계정, 대량 확보, 보안조치 우회 목적 사용을 지원하지 않습니다."
            ),
            justify=tk.LEFT,
            fg="#8A0000",
            bg="#FFF0F0",
            bd=1,
            relief=tk.SOLID,
            padx=10,
            pady=8,
            font=("Malgun Gothic", 10, "bold"),
        )
        warning.grid(row=0, column=0, sticky="ew")

        settings = ttk.LabelFrame(parent, text="보조 실행 설정", padding=12)
        settings.grid(row=1, column=0, sticky="ew", pady=(12, 10))
        settings.columnconfigure(1, weight=1)

        ttk.Label(settings, text="기본 대기(ms)").grid(row=0, column=0, sticky="w")
        self._spinbox(settings, self.routine_click_delay_var, MIN_PRE_CLICK_WAIT_MS, 5000, width=8).grid(
            row=0, column=1, sticky="w", padx=(10, 0)
        )
        ttk.Label(settings, text="한 바퀴 대기(ms)").grid(
            row=1, column=0, sticky="w", pady=(8, 0)
        )
        self._spinbox(settings, self.routine_cycle_delay_var, MIN_ROUTINE_CYCLE_DELAY_MS, 5000, width=8).grid(
            row=1, column=1, sticky="w", padx=(10, 0), pady=(8, 0)
        )
        ttk.Label(settings, text="발견 후 보조 좌표 간격(ms)").grid(
            row=2, column=0, sticky="w", pady=(8, 0)
        )
        self._spinbox(settings, self.post_click_delay_var, MIN_POST_CLICK_DELAY_MS, 5000, width=8).grid(
            row=2, column=1, sticky="w", padx=(10, 0), pady=(8, 0)
        )
        ttk.Label(settings, text="최대 반복(0=무제한)").grid(
            row=3, column=0, sticky="w", pady=(8, 0)
        )
        self._spinbox(settings, self.max_cycles_var, 0, 9999, width=8).grid(
            row=3, column=1, sticky="w", padx=(10, 0), pady=(8, 0)
        )
        ttk.Checkbutton(
            settings,
            text="대상 색상 발견 시 자동 클릭(기본 OFF)",
            variable=self.auto_click_on_match_var,
        ).grid(row=4, column=0, columnspan=2, sticky="w", pady=(10, 0))
        ttk.Checkbutton(
            settings,
            text="자동 클릭 안전 고지 확인",
            variable=self.auto_click_safety_ack_var,
        ).grid(row=5, column=0, columnspan=2, sticky="w", pady=(6, 0))
        ttk.Label(
            settings,
            text="최종 결제/약관 동의/구매 확정/주문 제출 좌표에는 사용할 수 없습니다.",
            foreground="#8A0000",
            wraplength=360,
        ).grid(row=6, column=0, columnspan=2, sticky="w", pady=(2, 0))
        ttk.Checkbutton(
            settings,
            text="발견 후 선택적 보조 좌표 실행(실행 전 확인 필요)",
            variable=self.run_post_points_var,
        ).grid(row=7, column=0, columnspan=2, sticky="w", pady=(6, 0))
        ttk.Checkbutton(
            settings,
            text="자동 클릭 후 화면 변화 하드 판단",
            variable=self.confirm_selection_var,
        ).grid(row=8, column=0, columnspan=2, sticky="w", pady=(6, 0))
        ttk.Label(settings, text="판단 대기(ms)").grid(
            row=9, column=0, sticky="w", pady=(8, 0)
        )
        self._spinbox(settings, self.confirm_wait_var, 150, 3000, width=8).grid(
            row=9, column=1, sticky="w", padx=(10, 0), pady=(8, 0)
        )

        pre_frame = ttk.LabelFrame(parent, text="탐지 전 사용자 지정 보조 좌표", padding=12)
        pre_frame.grid(row=2, column=0, sticky="nsew", pady=(0, 10))
        pre_frame.columnconfigure(0, weight=1)
        self.pre_tree = ttk.Treeview(
            pre_frame,
            columns=("order", "point", "wait"),
            show="headings",
            height=5,
            selectmode="browse",
        )
        self.pre_tree.heading("order", text="#")
        self.pre_tree.heading("point", text="좌표")
        self.pre_tree.heading("wait", text="대기(s)")
        self.pre_tree.column("order", width=42, anchor=tk.CENTER, stretch=False)
        self.pre_tree.column("point", width=170, anchor=tk.CENTER)
        self.pre_tree.column("wait", width=86, anchor=tk.CENTER, stretch=False)
        self.pre_tree.grid(row=0, column=0, columnspan=5, sticky="ew")
        self.pre_tree.bind("<Double-1>", self.edit_pre_point_wait)
        ttk.Button(
            pre_frame,
            text="화면에서 찍기",
            command=lambda: self.start_point_picker("pre"),
        ).grid(row=1, column=0, sticky="ew", pady=(8, 0))
        ttk.Button(
            pre_frame,
            text="좌표 값 입력",
            command=lambda: self.open_point_input("pre"),
        ).grid(row=1, column=1, sticky="ew", padx=(6, 0), pady=(8, 0))
        ttk.Button(
            pre_frame,
            text="좌표 보기",
            command=lambda: self.show_point_sequence("pre"),
        ).grid(row=1, column=2, sticky="ew", padx=(6, 0), pady=(8, 0))
        ttk.Button(
            pre_frame,
            text="삭제",
            command=lambda: self.delete_selected_point("pre"),
        ).grid(row=1, column=3, sticky="ew", padx=(6, 0), pady=(8, 0))
        ttk.Button(
            pre_frame,
            text="전체삭제",
            command=lambda: self.clear_points("pre"),
        ).grid(row=1, column=4, sticky="ew", padx=(6, 0), pady=(8, 0))

        post_frame = ttk.LabelFrame(parent, text="발견 후 선택적 보조 좌표", padding=12)
        post_frame.grid(row=3, column=0, sticky="nsew", pady=(0, 10))
        post_frame.columnconfigure(0, weight=1)
        self.post_listbox = tk.Listbox(post_frame, height=5, activestyle="dotbox")
        self.post_listbox.grid(row=0, column=0, columnspan=5, sticky="ew")
        ttk.Button(
            post_frame,
            text="화면에서 찍기",
            command=lambda: self.start_point_picker("post"),
        ).grid(row=1, column=0, sticky="ew", pady=(8, 0))
        ttk.Button(
            post_frame,
            text="좌표 값 입력",
            command=lambda: self.open_point_input("post"),
        ).grid(row=1, column=1, sticky="ew", padx=(6, 0), pady=(8, 0))
        ttk.Button(
            post_frame,
            text="좌표 보기",
            command=lambda: self.show_point_sequence("post"),
        ).grid(row=1, column=2, sticky="ew", padx=(6, 0), pady=(8, 0))
        ttk.Button(
            post_frame,
            text="삭제",
            command=lambda: self.delete_selected_point("post"),
        ).grid(row=1, column=3, sticky="ew", padx=(6, 0), pady=(8, 0))
        ttk.Button(
            post_frame,
            text="전체삭제",
            command=lambda: self.clear_points("post"),
        ).grid(row=1, column=4, sticky="ew", padx=(6, 0), pady=(8, 0))

        controls = ttk.Frame(parent)
        controls.grid(row=4, column=0, sticky="ew")
        self.routine_start_button = ttk.Button(
            controls,
            text="보조 실행",
            command=self.start_routine,
        )
        self.routine_start_button.pack(side=tk.LEFT)
        ttk.Button(
            controls,
            text="보조 정지",
            command=self.stop_scan,
        ).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(
            controls,
            text="저장",
            command=self.save_routine,
        ).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(
            controls,
            text="불러오기",
            command=self.load_routine,
        ).pack(side=tk.LEFT, padx=(8, 0))

        hint = ttk.Label(
            parent,
            text=(
                "기본 동작: 보조 좌표 클릭 -> 대상 색상 검사 -> 발견 위치로 마우스 이동 -> 정지. "
                "자동 클릭과 발견 후 보조 좌표는 별도 안전 확인이 있을 때만 실행됩니다."
            ),
            wraplength=400,
            justify=tk.LEFT,
        )
        hint.grid(row=5, column=0, sticky="ew", pady=(10, 0))

    def _show_notice(self) -> None:
        messagebox.showwarning("공개 사용 안전 고지", NOTICE_TEXT, parent=self.root)

    def _close(self) -> None:
        self._finish_eyedropper(keep=False, update_status=False)
        self._finish_region_selection(update_status=False)
        self._finish_point_picker(update_status=False)
        if self.point_input_close is not None:
            self.point_input_close()
        if self.preview_after_id is not None:
            self.root.after_cancel(self.preview_after_id)
            self.preview_after_id = None
        self.stop_scan()
        self.root.destroy()

    def _update_tolerance_label(self) -> None:
        value = int(float(self.tolerance_var.get()))
        self.tolerance_label_var.set(f"비슷한 색상 허용 오차: ±{value}")

    def _update_target_display(self) -> None:
        hex_color = rgb_to_hex(self.target_color)
        self.hex_var.set(hex_color)
        self.red_var.set(str(self.target_color[0]))
        self.green_var.set(str(self.target_color[1]))
        self.blue_var.set(str(self.target_color[2]))
        self.preview.itemconfigure(self.preview_rect, fill=hex_color)

    def set_target_color(
        self, rgb: tuple[int, int, int], status: str | None = None
    ) -> None:
        self.target_color = tuple(clamp(int(channel), 0, 255) for channel in rgb)
        self._update_target_display()
        if status:
            self.status_var.set(status)

    def _read_int_var(
        self, variable: tk.Variable, field_name: str, minimum: int, maximum: int
    ) -> int:
        try:
            value = int(variable.get())
        except (tk.TclError, ValueError) as exc:
            raise ValueError(f"{field_name} 값은 숫자로 입력하세요.") from exc
        if value < minimum or value > maximum:
            raise ValueError(f"{field_name} 값은 {minimum}부터 {maximum} 사이여야 합니다.")
        return value

    def apply_rgb(self) -> None:
        try:
            red = self._read_int_var(self.red_var, "R", 0, 255)
            green = self._read_int_var(self.green_var, "G", 0, 255)
            blue = self._read_int_var(self.blue_var, "B", 0, 255)
        except ValueError as exc:
            messagebox.showerror("RGB 입력 오류", str(exc), parent=self.root)
            return

        self.set_target_color((red, green, blue), "RGB 값으로 찾을 대상 색상을 지정했습니다.")

    def choose_color(self) -> None:
        result, _hex = colorchooser.askcolor(
            color=rgb_to_hex(self.target_color),
            title="찾을 대상 색상 선택",
            parent=self.root,
        )
        if result:
            rgb = tuple(int(round(channel)) for channel in result)
            self.set_target_color(rgb, "색상 선택기로 찾을 대상 색상을 지정했습니다.")

    def toggle_eyedropper(self) -> None:
        if self.eyedropper_active:
            self._finish_eyedropper(keep=False)
            return

        self.color_before_eyedropper = self.target_color
        self.eyedropper_active = True
        self.eyedropper_button.configure(text="스포이드 취소")
        self.status_var.set(
            "스포이드 활성화: 원하는 색상 위에서 왼쪽 클릭하면 선택됩니다. Esc 또는 오른쪽 클릭으로 취소합니다."
        )
        self.eyedropper_overlay = EyedropperOverlay(
            self.root,
            self.screen,
            self._pick_eyedropper_color,
            self._cancel_eyedropper,
            self._handle_eyedropper_error,
        )

    def _pick_eyedropper_color(
        self, rgb: tuple[int, int, int], x: int, y: int
    ) -> None:
        self.eyedropper_overlay = None
        self._finish_eyedropper(keep=True, update_status=False)
        self.set_target_color(
            rgb,
            f"스포이드로 선택 완료: ({x}, {y}) RGB {rgb[0]}, {rgb[1]}, {rgb[2]}",
        )

    def _cancel_eyedropper(self, _event: tk.Event | None = None) -> None:
        self._finish_eyedropper(keep=False)

    def _handle_eyedropper_error(self, exc: Exception) -> None:
        self.eyedropper_overlay = None
        self._finish_eyedropper(keep=False, update_status=False)
        self.status_var.set(f"스포이드 오류: {exc}")

    def _finish_eyedropper(self, keep: bool, update_status: bool = True) -> None:
        if not self.eyedropper_active:
            return

        if self.eyedropper_overlay:
            overlay = self.eyedropper_overlay
            self.eyedropper_overlay = None
            overlay.close()

        self.eyedropper_active = False
        self.eyedropper_button.configure(text="스포이드 시작")

        if keep and update_status:
            self.status_var.set("스포이드로 찾을 대상 색상을 지정했습니다.")
        elif not keep:
            self.set_target_color(
                self.color_before_eyedropper,
                "스포이드 선택을 취소했습니다." if update_status else None,
            )

    def start_region_selection(self) -> None:
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showinfo(
                "탐지 중",
                "탐지를 정지한 뒤 영역을 다시 선택하세요.",
                parent=self.root,
            )
            return

        if self.eyedropper_active:
            self._finish_eyedropper(keep=False)

        if self.region_overlay:
            self._finish_region_selection()
            return

        self.region_button.configure(text="영역 선택 취소")
        self.status_var.set(
            "탐지 캡처 영역 선택: 대상 색상을 찾을 화면 부분만 드래그하세요. Esc 또는 오른쪽 클릭으로 취소합니다."
        )
        self.region_overlay = RegionSelectorOverlay(
            self.root,
            self.screen,
            self._set_scan_region,
            self._cancel_region_selection,
        )

    def _set_scan_region(self, region: tuple[int, int, int, int]) -> None:
        self.region_overlay = None
        self.region_button.configure(text="드래그로 탐지 영역 지정")
        self.scan_region = region
        self.region_var.set(format_region(region))
        self.status_var.set(f"색상 탐지 범위를 지정했습니다: {format_region(region)} 안에서만 찾습니다.")
        self.update_capture_preview_once()

    def _cancel_region_selection(self) -> None:
        self.region_overlay = None
        self.region_button.configure(text="드래그로 탐지 영역 지정")
        self.status_var.set("탐지 캡처 영역 선택을 취소했습니다.")

    def _finish_region_selection(self, update_status: bool = True) -> None:
        if not self.region_overlay:
            return

        overlay = self.region_overlay
        self.region_overlay = None
        overlay.close()
        self.region_button.configure(text="드래그로 탐지 영역 지정")
        if update_status:
            self.status_var.set("탐지 캡처 영역 선택을 취소했습니다.")

    def clear_scan_region(self) -> None:
        self._finish_region_selection(update_status=False)
        self.scan_region = None
        self.region_var.set(format_region(None))
        self.status_var.set("색상 탐지 범위를 전체 화면 캡처로 되돌렸습니다.")
        self.update_capture_preview_once()

    def _points_for_kind(self, kind: str) -> list:
        return self.pre_routine_points if kind == "pre" else self.post_routine_points

    def _kind_label(self, kind: str) -> str:
        return "탐지 전 사용자 지정 보조" if kind == "pre" else "발견 후 선택적 보조"

    def _refresh_point_list(self, kind: str) -> None:
        if kind == "pre":
            for item_id in self.pre_tree.get_children():
                self.pre_tree.delete(item_id)
            for index, (x, y, wait_ms) in enumerate(self.pre_routine_points, start=1):
                self.pre_tree.insert(
                    "",
                    tk.END,
                    iid=str(index - 1),
                    values=(f"{index:02d}", f"x={x}, y={y}", f"{wait_ms / 1000:.2f}"),
                )
            return

        self.post_listbox.delete(0, tk.END)
        for index, (x, y) in enumerate(self.post_routine_points, start=1):
            self.post_listbox.insert(tk.END, f"{index:02d}. x={x}, y={y}")

    def _selected_point_index(self, kind: str) -> int | None:
        if kind == "pre":
            selected = self.pre_tree.selection()
            if not selected:
                return None
            try:
                return int(selected[0])
            except ValueError:
                return None

        selected = self.post_listbox.curselection()
        return selected[0] if selected else None

    def _point_xy_at(self, kind: str, index: int) -> Coordinate | None:
        points = self._points_for_kind(kind)
        if index < 0 or index >= len(points):
            return None
        point = points[index]
        if kind == "pre":
            x, y, _wait_ms = point
            return x, y
        x, y = point
        return x, y

    def start_point_picker(self, kind: str) -> None:
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showinfo(
                "실행 중",
                "탐지나 보조 실행을 정지한 뒤 좌표를 추가하세요.",
                parent=self.root,
            )
            return

        if self.eyedropper_active:
            self._finish_eyedropper(keep=False)
        if self.region_overlay:
            self._finish_region_selection(update_status=False)
        if self.point_picker_overlay:
            self._finish_point_picker()
            return

        self.pending_point_kind = kind
        label = self._kind_label(kind)
        self.status_var.set(f"{label} 좌표 찍기: 저장할 위치를 클릭하세요.")
        self.point_picker_overlay = PointPickerOverlay(
            self.root,
            self.screen,
            label,
            self._add_picked_point,
            self._cancel_point_picker,
        )

    def _add_picked_point(self, x: int, y: int) -> None:
        kind = self.pending_point_kind or "pre"
        self.point_picker_overlay = None
        self.pending_point_kind = None
        if kind == "pre":
            self.pre_routine_points.append(
                (x, y, self._read_default_pre_wait_ms(silent=True))
            )
        else:
            self.post_routine_points.append((x, y))
        self._refresh_point_list(kind)
        self.status_var.set(f"{self._kind_label(kind)} 좌표를 추가했습니다: x={x}, y={y}")

    def _cancel_point_picker(self) -> None:
        self.point_picker_overlay = None
        self.pending_point_kind = None
        self.status_var.set("좌표 찍기를 취소했습니다.")

    def _finish_point_picker(self, update_status: bool = True) -> None:
        if not self.point_picker_overlay:
            return
        overlay = self.point_picker_overlay
        self.point_picker_overlay = None
        self.pending_point_kind = None
        overlay.close()
        if update_status:
            self.status_var.set("좌표 찍기를 취소했습니다.")

    def open_point_input(self, kind: str) -> None:
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showinfo(
                "실행 중",
                "탐지나 보조 실행을 정지한 뒤 좌표를 추가하세요.",
                parent=self.root,
            )
            return

        if self.point_input_close is not None:
            self.point_input_close()

        dialog = tk.Toplevel(self.root)
        dialog.title(f"{self._kind_label(kind)} 좌표 값 입력")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        frame = ttk.Frame(dialog, padding=14)
        frame.pack(fill=tk.BOTH, expand=True)

        live_var = tk.StringVar(value="현재 마우스: 확인 중")
        x_var = tk.StringVar()
        y_var = tk.StringVar()

        ttk.Label(frame, textvariable=live_var, font=("Consolas", 10, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w"
        )
        ttk.Label(frame, text="X").grid(row=1, column=0, sticky="w", pady=(10, 0))
        x_entry = ttk.Entry(frame, textvariable=x_var, width=12, justify=tk.CENTER)
        x_entry.grid(row=1, column=1, sticky="w", padx=(10, 0), pady=(10, 0))
        ttk.Label(frame, text="Y").grid(row=2, column=0, sticky="w", pady=(8, 0))
        y_entry = ttk.Entry(frame, textvariable=y_var, width=12, justify=tk.CENTER)
        y_entry.grid(row=2, column=1, sticky="w", padx=(10, 0), pady=(8, 0))

        if kind == "pre":
            wait_var = tk.StringVar(
                value=f"{self._read_default_pre_wait_ms(silent=True) / 1000:.2f}"
            )
            ttk.Label(frame, text="클릭 후 대기(초)").grid(
                row=3, column=0, sticky="w", pady=(8, 0)
            )
            ttk.Entry(frame, textvariable=wait_var, width=12, justify=tk.CENTER).grid(
                row=3, column=1, sticky="w", padx=(10, 0), pady=(8, 0)
            )
        else:
            wait_var = None

        after_id: list[str | None] = [None]

        def poll_mouse() -> None:
            try:
                x, y = self.screen.cursor_position()
                live_var.set(f"현재 마우스: x={x}, y={y}")
            except OSError as exc:
                live_var.set(f"현재 마우스: 오류 {exc}")
            after_id[0] = dialog.after(100, poll_mouse)

        def close_dialog() -> None:
            if after_id[0] is not None:
                dialog.after_cancel(after_id[0])
                after_id[0] = None
            self.point_input_close = None
            dialog.destroy()

        def add_point() -> None:
            try:
                x = int(x_var.get())
                y = int(y_var.get())
            except ValueError:
                messagebox.showerror("좌표 입력 오류", "X/Y는 숫자로 입력하세요.", parent=dialog)
                return

            if kind == "pre":
                try:
                    seconds = float(
                        wait_var.get()
                        if wait_var is not None
                        else str(DEFAULT_PRE_CLICK_WAIT_MS / 1000)
                    )
                except ValueError:
                    messagebox.showerror("대기시간 오류", "대기시간은 숫자로 입력하세요.", parent=dialog)
                    return
                min_seconds = MIN_PRE_CLICK_WAIT_MS / 1000
                if seconds < min_seconds or seconds > 5:
                    messagebox.showerror(
                        "대기시간 오류",
                        f"{min_seconds:.2f}초부터 5초 사이로 입력하세요.",
                        parent=dialog,
                    )
                    return
                self.pre_routine_points.append((x, y, int(round(seconds * 1000))))
            else:
                self.post_routine_points.append((x, y))

            self._refresh_point_list(kind)
            self.status_var.set(f"{self._kind_label(kind)} 좌표 값을 추가했습니다: x={x}, y={y}")
            close_dialog()

        buttons = ttk.Frame(frame)
        buttons.grid(row=4, column=0, columnspan=2, sticky="e", pady=(14, 0))
        ttk.Button(buttons, text="추가", command=add_point).pack(side=tk.LEFT)
        ttk.Button(buttons, text="취소", command=close_dialog).pack(side=tk.LEFT, padx=(6, 0))

        dialog.protocol("WM_DELETE_WINDOW", close_dialog)
        self.point_input_close = close_dialog
        dialog.bind("<Return>", lambda _event: add_point())
        dialog.bind("<Escape>", lambda _event: close_dialog())
        x_entry.focus_set()
        poll_mouse()

    def add_current_point(self, kind: str) -> None:
        try:
            x, y = self.screen.cursor_position()
        except OSError as exc:
            messagebox.showerror("좌표 오류", str(exc), parent=self.root)
            return
        if kind == "pre":
            self.pre_routine_points.append(
                (x, y, self._read_default_pre_wait_ms(silent=True))
            )
        else:
            self.post_routine_points.append((x, y))
        self._refresh_point_list(kind)
        self.status_var.set(f"{self._kind_label(kind)} 현재 좌표를 추가했습니다: x={x}, y={y}")

    def delete_selected_point(self, kind: str) -> None:
        index = self._selected_point_index(kind)
        if index is None:
            return
        points = self._points_for_kind(kind)
        if index < len(points):
            del points[index]
        self._refresh_point_list(kind)
        self.status_var.set(f"{self._kind_label(kind)} 좌표를 삭제했습니다.")

    def clear_points(self, kind: str) -> None:
        self._points_for_kind(kind).clear()
        self._refresh_point_list(kind)
        self.status_var.set(f"{self._kind_label(kind)} 좌표를 모두 삭제했습니다.")

    def _routine_payload(self) -> dict[str, object]:
        return {
            "version": 1,
            "target_color": list(self.target_color),
            "detection_capture_region": (
                list(self.scan_region) if self.scan_region else None
            ),
            "scan_region": list(self.scan_region) if self.scan_region else None,
            "scan_settings": {
                "tolerance": self._coerce_int(self.tolerance_var.get(), 18, 0, 80),
                "step": self._coerce_int(self.step_var.get(), 4, 1, 20),
                "interval_ms": self._coerce_int(
                    self.interval_var.get(),
                    DEFAULT_SCAN_INTERVAL_MS,
                    MIN_SCAN_INTERVAL_MS,
                    2000,
                ),
                "stop_on_first": bool(self.stop_on_first_var.get()),
            },
            "routine_settings": {
                "default_wait_ms": self._coerce_int(
                    self.routine_click_delay_var.get(),
                    DEFAULT_PRE_CLICK_WAIT_MS,
                    MIN_PRE_CLICK_WAIT_MS,
                    5000,
                ),
                "cycle_delay_ms": self._coerce_int(
                    self.routine_cycle_delay_var.get(),
                    DEFAULT_ROUTINE_CYCLE_DELAY_MS,
                    MIN_ROUTINE_CYCLE_DELAY_MS,
                    5000,
                ),
                "post_click_delay_ms": self._coerce_int(
                    self.post_click_delay_var.get(),
                    DEFAULT_POST_CLICK_DELAY_MS,
                    MIN_POST_CLICK_DELAY_MS,
                    5000,
                ),
                "max_cycles": self._coerce_int(
                    self.max_cycles_var.get(), DEFAULT_MAX_CYCLES, 0, 9999
                ),
                "auto_click_on_match": bool(self.auto_click_on_match_var.get()),
                "auto_click_safety_ack": bool(self.auto_click_safety_ack_var.get()),
                "run_post_points": bool(self.run_post_points_var.get()),
                "confirm_selection": bool(self.confirm_selection_var.get()),
                "confirm_wait_ms": self._coerce_int(
                    self.confirm_wait_var.get(), 900, 150, 3000
                ),
            },
            "pre_points": [
                {"x": x, "y": y, "wait_ms": wait_ms}
                for x, y, wait_ms in self.pre_routine_points
            ],
            "post_points": [
                {"x": x, "y": y}
                for x, y in self.post_routine_points
            ],
        }

    def save_routine(self) -> None:
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="보조 설정 저장",
            defaultextension=".json",
            filetypes=(("pixel assistant routine", "*.json"), ("All files", "*.*")),
            initialfile="pixel_assistant_routine.json",
        )
        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8") as file:
                json.dump(self._routine_payload(), file, ensure_ascii=False, indent=2)
        except OSError as exc:
            messagebox.showerror("저장 오류", str(exc), parent=self.root)
            return

        self.status_var.set(f"보조 설정을 저장했습니다: {path}")

    def load_routine(self) -> None:
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showinfo(
                "실행 중",
                "탐지나 보조 실행을 정지한 뒤 불러오세요.",
                parent=self.root,
            )
            return

        path = filedialog.askopenfilename(
            parent=self.root,
            title="보조 설정 불러오기",
            filetypes=(("pixel assistant routine", "*.json"), ("All files", "*.*")),
        )
        if not path:
            return

        try:
            with open(path, "r", encoding="utf-8") as file:
                payload = json.load(file)
            self._apply_loaded_routine(payload)
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            messagebox.showerror("불러오기 오류", str(exc), parent=self.root)
            return

        self.status_var.set(f"보조 설정을 불러왔습니다: {path}")

    def _coerce_int(
        self,
        value: object,
        default: int,
        minimum: int | None = None,
        maximum: int | None = None,
    ) -> int:
        try:
            result = int(value)
        except (tk.TclError, TypeError, ValueError):
            result = default
        if minimum is not None:
            result = max(minimum, result)
        if maximum is not None:
            result = min(maximum, result)
        return result

    def _apply_loaded_routine(self, payload: object) -> None:
        if not isinstance(payload, dict):
            raise ValueError("보조 설정 파일 형식이 올바르지 않습니다.")

        target_color = payload.get("target_color", self.target_color)
        if isinstance(target_color, list) and len(target_color) == 3:
            self.target_color = tuple(
                self._coerce_int(channel, 0, 0, 255) for channel in target_color
            )
            self._update_target_display()

        scan_region = payload.get("detection_capture_region")
        if scan_region is None:
            scan_region = payload.get("scan_region")
        if isinstance(scan_region, list) and len(scan_region) == 4:
            left, top, width, height = (
                self._coerce_int(scan_region[0], 0),
                self._coerce_int(scan_region[1], 0),
                self._coerce_int(scan_region[2], 1, 1),
                self._coerce_int(scan_region[3], 1, 1),
            )
            self.scan_region = (left, top, width, height)
        else:
            self.scan_region = None
        self.region_var.set(format_region(self.scan_region))

        scan_settings = payload.get("scan_settings", {})
        if isinstance(scan_settings, dict):
            self.tolerance_var.set(
                self._coerce_int(scan_settings.get("tolerance"), 18, 0, 80)
            )
            self.step_var.set(self._coerce_int(scan_settings.get("step"), 4, 1, 20))
            self.interval_var.set(
                self._coerce_int(
                    scan_settings.get("interval_ms"),
                    DEFAULT_SCAN_INTERVAL_MS,
                    MIN_SCAN_INTERVAL_MS,
                    2000,
                )
            )
            self.stop_on_first_var.set(bool(scan_settings.get("stop_on_first", True)))
            self._update_tolerance_label()

        routine_settings = payload.get("routine_settings", {})
        load_warnings: list[str] = []
        loaded_auto_click = False
        loaded_run_post_points = False
        if isinstance(routine_settings, dict):
            self.routine_click_delay_var.set(
                self._coerce_int(
                    routine_settings.get("default_wait_ms"),
                    DEFAULT_PRE_CLICK_WAIT_MS,
                    MIN_PRE_CLICK_WAIT_MS,
                    5000,
                )
            )
            self.routine_cycle_delay_var.set(
                self._coerce_int(
                    routine_settings.get("cycle_delay_ms"),
                    DEFAULT_ROUTINE_CYCLE_DELAY_MS,
                    MIN_ROUTINE_CYCLE_DELAY_MS,
                    5000,
                )
            )
            self.post_click_delay_var.set(
                self._coerce_int(
                    routine_settings.get("post_click_delay_ms"),
                    DEFAULT_POST_CLICK_DELAY_MS,
                    MIN_POST_CLICK_DELAY_MS,
                    5000,
                )
            )
            self.max_cycles_var.set(
                self._coerce_int(
                    routine_settings.get("max_cycles"), DEFAULT_MAX_CYCLES, 0, 9999
                )
            )
            loaded_auto_click = bool(routine_settings.get("auto_click_on_match", False))
            loaded_run_post_points = bool(routine_settings.get("run_post_points", False))
            self.confirm_wait_var.set(
                self._coerce_int(routine_settings.get("confirm_wait_ms"), 900, 150, 3000)
            )
        self.auto_click_on_match_var.set(False)
        self.auto_click_safety_ack_var.set(False)
        self.run_post_points_var.set(False)
        self.confirm_selection_var.set(True)
        if loaded_auto_click:
            load_warnings.append("자동 클릭 설정은 안전을 위해 OFF로 불러왔습니다.")
        if loaded_run_post_points:
            load_warnings.append("발견 후 보조 좌표 자동 실행 설정은 OFF로 불러왔습니다.")

        pre_points: list[RoutinePoint] = []
        for point in payload.get("pre_points", []):
            if isinstance(point, dict):
                x = self._coerce_int(point.get("x"), 0)
                y = self._coerce_int(point.get("y"), 0)
                wait_ms = self._coerce_int(
                    point.get("wait_ms"),
                    DEFAULT_PRE_CLICK_WAIT_MS,
                    MIN_PRE_CLICK_WAIT_MS,
                    5000,
                )
                pre_points.append((x, y, wait_ms))
            elif isinstance(point, list) and len(point) >= 2:
                x = self._coerce_int(point[0], 0)
                y = self._coerce_int(point[1], 0)
                wait_ms = self._coerce_int(
                    point[2] if len(point) > 2 else DEFAULT_PRE_CLICK_WAIT_MS,
                    DEFAULT_PRE_CLICK_WAIT_MS,
                    MIN_PRE_CLICK_WAIT_MS,
                    5000,
                )
                pre_points.append((x, y, wait_ms))
        self.pre_routine_points = pre_points

        post_points: list[Coordinate] = []
        for point in payload.get("post_points", []):
            if isinstance(point, dict):
                post_points.append(
                    (
                        self._coerce_int(point.get("x"), 0),
                        self._coerce_int(point.get("y"), 0),
                    )
                )
            elif isinstance(point, list) and len(point) >= 2:
                post_points.append(
                    (
                        self._coerce_int(point[0], 0),
                        self._coerce_int(point[1], 0),
                    )
                )
        self.post_routine_points = post_points
        if post_points:
            load_warnings.append(
                "발견 후 선택적 보조 좌표가 포함되어 있습니다. 실행 옵션은 OFF이며, "
                "사용 전 결제/약관/구매확정/주문 제출 좌표가 아닌지 직접 확인하세요."
            )

        self._refresh_point_list("pre")
        self._refresh_point_list("post")
        self.update_capture_preview_once()
        if load_warnings:
            messagebox.showwarning(
                "보조 설정 안전 확인",
                "\n\n".join(load_warnings),
                parent=self.root,
            )

    def _read_default_pre_wait_ms(self, silent: bool = False) -> int:
        try:
            return self._read_int_var(
                self.routine_click_delay_var,
                "기본 대기",
                MIN_PRE_CLICK_WAIT_MS,
                5000,
            )
        except ValueError as exc:
            if not silent:
                messagebox.showerror("대기시간 오류", str(exc), parent=self.root)
            return DEFAULT_PRE_CLICK_WAIT_MS

    def edit_pre_point_wait(self, _event: tk.Event | None = None) -> None:
        index = self._selected_point_index("pre")
        if index is None or index >= len(self.pre_routine_points):
            return

        x, y, wait_ms = self.pre_routine_points[index]
        editor = tk.Toplevel(self.root)
        editor.title("대기시간 설정")
        editor.resizable(False, False)
        editor.transient(self.root)
        editor.grab_set()

        frame = ttk.Frame(editor, padding=14)
        frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frame, text=f"x={x}, y={y}").grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Label(frame, text="클릭 후 대기(초)").grid(row=1, column=0, sticky="w", pady=(10, 0))
        seconds_var = tk.StringVar(value=f"{wait_ms / 1000:.2f}")
        entry = ttk.Entry(frame, textvariable=seconds_var, width=10, justify=tk.CENTER)
        entry.grid(row=1, column=1, sticky="w", padx=(10, 0), pady=(10, 0))

        def apply_wait() -> None:
            try:
                seconds = float(seconds_var.get())
            except ValueError:
                messagebox.showerror("대기시간 오류", "숫자로 입력하세요.", parent=editor)
                return
            min_seconds = MIN_PRE_CLICK_WAIT_MS / 1000
            if seconds < min_seconds or seconds > 5:
                messagebox.showerror(
                    "대기시간 오류",
                    f"{min_seconds:.2f}초부터 5초 사이로 입력하세요.",
                    parent=editor,
                )
                return
            self.pre_routine_points[index] = (x, y, int(round(seconds * 1000)))
            self._refresh_point_list("pre")
            self.pre_tree.selection_set(str(index))
            self.status_var.set(f"반복 좌표 {index + 1}번 대기시간을 {seconds:.2f}초로 설정했습니다.")
            editor.destroy()

        buttons = ttk.Frame(frame)
        buttons.grid(row=2, column=0, columnspan=2, sticky="e", pady=(14, 0))
        ttk.Button(buttons, text="적용", command=apply_wait).pack(side=tk.LEFT)
        ttk.Button(buttons, text="취소", command=editor.destroy).pack(side=tk.LEFT, padx=(6, 0))
        entry.focus_set()
        entry.selection_range(0, tk.END)
        editor.bind("<Return>", lambda _event: apply_wait())
        editor.bind("<Escape>", lambda _event: editor.destroy())

    def show_point_sequence(self, kind: str) -> None:
        markers: list[tuple[int, int, str]] = []
        if kind == "pre":
            for index, (x, y, wait_ms) in enumerate(self.pre_routine_points, start=1):
                markers.append((x, y, f"{index}\n{wait_ms / 1000:.2f}s"))
        else:
            try:
                delay_ms = self._read_int_var(
                    self.post_click_delay_var,
                    "발견 후 보조 좌표 간격",
                    MIN_POST_CLICK_DELAY_MS,
                    5000,
                )
            except ValueError:
                delay_ms = DEFAULT_POST_CLICK_DELAY_MS
            for index, (x, y) in enumerate(self.post_routine_points, start=1):
                markers.append((x, y, f"{index}\n{delay_ms / 1000:.2f}s"))

        if not markers:
            self.status_var.set(f"{self._kind_label(kind)} 좌표가 없습니다.")
            return

        self.show_point_markers(markers)
        self.status_var.set(
            f"{self._kind_label(kind)} 좌표 {len(markers)}개를 순서와 대기시간으로 표시했습니다."
        )

    def show_point_markers(
        self,
        markers: list[tuple[int, int, str]],
        duration_ms: int = 1000,
    ) -> None:
        left, top, width, height = self.screen.virtual_bounds()
        marker = tk.Toplevel(self.root)
        marker.withdraw()
        marker.overrideredirect(True)
        marker.configure(bg="#FF00FF")
        marker.geometry(f"{width}x{height}{left:+d}{top:+d}")
        marker.attributes("-topmost", True)
        try:
            marker.attributes("-transparentcolor", "#FF00FF")
        except tk.TclError:
            marker.attributes("-alpha", 0.35)

        canvas = tk.Canvas(
            marker,
            bg="#FF00FF",
            bd=0,
            highlightthickness=0,
        )
        canvas.pack(fill=tk.BOTH, expand=True)

        local_points = [(x - left, y - top, label) for x, y, label in markers]
        for index in range(len(local_points) - 1):
            x1, y1, _label1 = local_points[index]
            x2, y2, _label2 = local_points[index + 1]
            canvas.create_line(
                x1,
                y1,
                x2,
                y2,
                fill="#FFB000",
                width=3,
                dash=(8, 6),
            )

        radius = 22
        for local_x, local_y, label in local_points:
            canvas.create_oval(
                local_x - radius,
                local_y - radius,
                local_x + radius,
                local_y + radius,
                outline="#FF2D2D",
                width=5,
            )
            canvas.create_oval(
                local_x - 8,
                local_y - 8,
                local_x + 8,
                local_y + 8,
                outline="#FFFFFF",
                width=3,
            )

            label_x = clamp(local_x + 28, 8, max(8, width - 92))
            label_y = clamp(local_y - 20, 8, max(8, height - 52))
            canvas.create_rectangle(
                label_x - 6,
                label_y - 4,
                label_x + 74,
                label_y + 42,
                fill="#FFFFFF",
                outline="#111111",
                width=1,
            )
            canvas.create_text(
                label_x + 34,
                label_y + 19,
                text=label,
                fill="#111111",
                font=("Consolas", 10, "bold"),
                justify=tk.CENTER,
            )

        marker.deiconify()
        marker.lift()
        marker.after(duration_ms, marker.destroy)

    def _capture_detection_area(
        self,
        region: tuple[int, int, int, int] | None,
    ) -> tuple[bytes, int, int, int, int]:
        if region:
            return self.screen.capture_region(*region)
        return self.screen.capture_screen()

    def update_capture_preview_once(self) -> None:
        try:
            data, left, top, width, height = self._capture_detection_area(
                self.scan_region
            )
            canvas_width = max(1, self.capture_preview_canvas.winfo_width())
            canvas_height = max(1, self.capture_preview_canvas.winfo_height())
            if canvas_width < 20:
                canvas_width = 580
            if canvas_height < 20:
                canvas_height = 190

            ppm_data, preview_width, preview_height = capture_to_ppm_preview(
                data,
                width,
                height,
                canvas_width - 8,
                canvas_height - 8,
            )
            self.capture_preview_image = tk.PhotoImage(data=ppm_data, format="PPM")
            self.capture_preview_canvas.delete("preview")
            self.capture_preview_canvas.delete("placeholder")
            self.capture_preview_canvas.create_image(
                canvas_width // 2,
                canvas_height // 2,
                image=self.capture_preview_image,
                anchor=tk.CENTER,
                tags="preview",
            )
            self.capture_preview_canvas.create_rectangle(
                (canvas_width - preview_width) // 2,
                (canvas_height - preview_height) // 2,
                (canvas_width + preview_width) // 2,
                (canvas_height + preview_height) // 2,
                outline="#4AA3FF",
                width=1,
                tags="preview",
            )
            self.preview_status_var.set(
                f"탐지 범위: {format_region((left, top, width, height))} | "
                f"프리뷰 {preview_width}x{preview_height}"
            )
        except Exception as exc:
            self.preview_status_var.set(f"탐지 캡처 프리뷰 오류: {exc}")

    def _toggle_live_preview(self) -> None:
        if self.live_preview_var.get():
            self._schedule_capture_preview(delay_ms=50)
        elif self.preview_after_id is not None:
            self.root.after_cancel(self.preview_after_id)
            self.preview_after_id = None

    def _schedule_capture_preview(self, delay_ms: int = 250) -> None:
        if not self.live_preview_var.get() or self.preview_after_id is not None:
            return
        self.preview_after_id = self.root.after(delay_ms, self._live_preview_tick)

    def _live_preview_tick(self) -> None:
        self.preview_after_id = None
        if not self.live_preview_var.get():
            return
        self.update_capture_preview_once()
        self._schedule_capture_preview()

    def _find_target_once(
        self,
        region: tuple[int, int, int, int] | None,
        target: tuple[int, int, int],
        tolerance: int,
        step: int,
    ) -> tuple[int, int, tuple[int, int, int]] | None:
        data, left, top, width, height = self._capture_detection_area(region)
        return find_matching_pixel(
            data,
            width,
            height,
            left,
            top,
            target,
            tolerance,
            step,
        )

    def _capture_click_patch(
        self, x: int, y: int, radius: int = 18
    ) -> tuple[bytes, int, int, int, int]:
        screen_left, screen_top, screen_width, screen_height = self.screen.virtual_bounds()
        left = clamp(x - radius, screen_left, screen_left + screen_width - 1)
        top = clamp(y - radius, screen_top, screen_top + screen_height - 1)
        right = clamp(x + radius + 1, screen_left + 1, screen_left + screen_width)
        bottom = clamp(y + radius + 1, screen_top + 1, screen_top + screen_height)
        return self.screen.capture_region(left, top, max(1, right - left), max(1, bottom - top))

    def _patch_changed_hard(self, before: bytes, after: bytes) -> tuple[bool, str]:
        if len(before) != len(after) or len(before) < 4:
            return False, "비교할 캡처 조각 크기가 다릅니다."

        pixel_count = len(before) // 4
        total_channel_delta = 0
        changed_pixels = 0
        max_pixel_delta = 0
        center_index = (pixel_count // 2) * 4
        center_delta = 0

        for offset in range(0, len(before), 4):
            delta = (
                abs(after[offset] - before[offset])
                + abs(after[offset + 1] - before[offset + 1])
                + abs(after[offset + 2] - before[offset + 2])
            )
            total_channel_delta += delta
            if delta >= 45:
                changed_pixels += 1
            if delta > max_pixel_delta:
                max_pixel_delta = delta
            if offset == center_index:
                center_delta = delta

        average_channel_delta = total_channel_delta / (pixel_count * 3)
        changed_ratio = changed_pixels / pixel_count

        center_changed = center_delta >= 30 and average_channel_delta >= 1.2
        border_changed = (
            changed_ratio >= 0.045
            and average_channel_delta >= 2.0
            and max_pixel_delta >= 70
        )
        confirmed = center_changed or border_changed
        details = (
            f"center={center_delta}, avg={average_channel_delta:.1f}, "
            f"changed={changed_ratio:.1%}, max={max_pixel_delta}"
        )
        return confirmed, details

    def _wait_for_click_confirmation(
        self,
        x: int,
        y: int,
        before_patch: bytes,
        wait_ms: int,
    ) -> tuple[bool, str]:
        deadline = time.perf_counter() + (wait_ms / 1000)
        last_details = "변화 없음"

        while not self.stop_event.is_set() and time.perf_counter() < deadline:
            if self.stop_event.wait(0.08):
                break
            after_patch, _left, _top, _width, _height = self._capture_click_patch(x, y)
            confirmed, details = self._patch_changed_hard(before_patch, after_patch)
            last_details = details
            if confirmed:
                return True, details

        return False, last_details

    def _ask_yes_no_from_worker(self, title: str, message: str) -> bool:
        result = {"answer": False}
        done = threading.Event()

        def ask() -> None:
            try:
                result["answer"] = messagebox.askyesno(
                    title,
                    message,
                    parent=self.root,
                )
            finally:
                done.set()

        self.root.after(0, ask)
        while not self.stop_event.is_set():
            if done.wait(0.05):
                return result["answer"]
        return False

    def _confirm_post_points_from_worker(self, count: int) -> bool:
        return self._ask_yes_no_from_worker(
            "발견 후 보조 좌표 확인",
            (
                f"발견 후 선택적 보조 좌표 {count}개를 실행하기 전 확인합니다.\n\n"
                "이 좌표들이 최종 결제, 약관 동의, 구매 확정, 주문 제출, "
                "보안조치 우회와 관련된 버튼이 아님을 확인합니까?"
            ),
        )

    def start_routine(self) -> None:
        if self.scan_thread and self.scan_thread.is_alive():
            return

        if self.eyedropper_active:
            self._finish_eyedropper(keep=False)
        if self.region_overlay:
            self._finish_region_selection(update_status=False)
        if self.point_picker_overlay:
            self._finish_point_picker(update_status=False)

        try:
            config = {
                "target": self.target_color,
                "tolerance": self._read_int_var(
                    self.tolerance_var, "허용 오차", 0, 80
                ),
                "step": self._read_int_var(self.step_var, "스캔 촘촘함", 1, 20),
                "region": self.scan_region,
                "pre_points": list(self.pre_routine_points),
                "post_points": list(self.post_routine_points),
                "cycle_delay": self._read_int_var(
                    self.routine_cycle_delay_var,
                    "한 바퀴 대기",
                    MIN_ROUTINE_CYCLE_DELAY_MS,
                    5000,
                ),
                "post_delay": self._read_int_var(
                    self.post_click_delay_var,
                    "발견 후 보조 좌표 간격",
                    MIN_POST_CLICK_DELAY_MS,
                    5000,
                ),
                "max_cycles": self._read_int_var(
                    self.max_cycles_var, "최대 반복", 0, 9999
                ),
                "auto_click_on_match": bool(self.auto_click_on_match_var.get()),
                "run_post_points": bool(self.run_post_points_var.get()),
                "confirm_selection": bool(self.confirm_selection_var.get()),
                "confirm_wait": self._read_int_var(
                    self.confirm_wait_var, "판단 대기", 150, 3000
                ),
            }
        except ValueError as exc:
            messagebox.showerror("보조 실행 설정 오류", str(exc), parent=self.root)
            return

        if config["auto_click_on_match"] and not self.auto_click_safety_ack_var.get():
            messagebox.showwarning(
                "자동 클릭 안전 확인 필요",
                (
                    "자동 클릭을 사용하려면 안전 고지 확인 체크박스를 먼저 켜야 합니다.\n\n"
                    "최종 결제/약관 동의/구매 확정/주문 제출 좌표에는 사용할 수 없습니다."
                ),
                parent=self.root,
            )
            return

        if config["run_post_points"] and not config["auto_click_on_match"]:
            messagebox.showwarning(
                "보조 좌표 실행 불가",
                "발견 후 선택적 보조 좌표는 대상 색상 자동 클릭이 켜진 경우에만 실행할 수 있습니다.",
                parent=self.root,
            )
            return

        if config["max_cycles"] == 0:
            answer = messagebox.askyesno(
                "무제한 반복 확인",
                (
                    "최대 반복 0은 사용자가 정지할 때까지 계속 실행됩니다.\n"
                    "공개용 기본값은 50회입니다. 그래도 무제한으로 실행할까요?"
                ),
                parent=self.root,
            )
            if not answer:
                return

        if len(config["pre_points"]) > MAX_PRE_POINT_WARNING_COUNT:
            answer = messagebox.askyesno(
                "보조 좌표 개수 확인",
                (
                    f"탐지 전 사용자 지정 보조 좌표가 {len(config['pre_points'])}개입니다.\n"
                    "좌표가 많을수록 의도하지 않은 클릭 위험이 커집니다. 계속할까요?"
                ),
                parent=self.root,
            )
            if not answer:
                return

        if not config["pre_points"]:
            answer = messagebox.askyesno(
                "보조 좌표 없음",
                "탐지 전 사용자 지정 보조 좌표가 없습니다. 클릭 없이 대상 색상만 계속 탐지할까요?",
                parent=self.root,
            )
            if not answer:
                return

        self.stop_event.clear()
        self.last_finish_message = "보조 실행이 정지되었습니다."
        self.start_button.configure(state=tk.DISABLED)
        self.stop_button.configure(state=tk.NORMAL)
        self.routine_start_button.configure(state=tk.DISABLED)
        self.status_var.set(
            f"보조 실행 중입니다. {format_region(self.scan_region)} 안에서만 대상 색상을 찾습니다."
        )

        self.scan_thread = threading.Thread(
            target=self._routine_loop, args=(config,), daemon=True
        )
        self.scan_thread.start()

    def _routine_loop(self, config: dict[str, object]) -> None:
        target = config["target"]  # type: ignore[assignment]
        tolerance = int(config["tolerance"])
        step = int(config["step"])
        region = config["region"]  # type: ignore[assignment]
        pre_points = config["pre_points"]  # type: ignore[assignment]
        post_points = config["post_points"]  # type: ignore[assignment]
        cycle_delay = int(config["cycle_delay"]) / 1000
        post_delay = int(config["post_delay"]) / 1000
        max_cycles = int(config["max_cycles"])
        auto_click_on_match = bool(config["auto_click_on_match"])
        run_post_points = bool(config["run_post_points"])
        confirm_selection = bool(config["confirm_selection"])
        confirm_wait = int(config["confirm_wait"])
        scan_area = format_region(region)  # type: ignore[arg-type]
        cycles = 0

        try:
            while not self.stop_event.is_set():
                match = self._find_target_once(
                    region,  # type: ignore[arg-type]
                    target,  # type: ignore[arg-type]
                    tolerance,
                    step,
                )
                if match:
                    self._handle_routine_match(
                        match,
                        post_points,
                        post_delay,
                        auto_click_on_match,
                        run_post_points,
                        confirm_selection,
                        confirm_wait,
                    )
                    return

                if pre_points:
                    for index, (x, y, wait_ms) in enumerate(pre_points, start=1):
                        if self.stop_event.is_set():
                            break
                        self.root.after(
                            0,
                            self.status_var.set,
                            f"보조 실행 중: {cycles + 1}회차 {index}/{len(pre_points)} 보조 클릭 x={x}, y={y}, 대기 {wait_ms / 1000:.2f}s",
                        )
                        self.screen.click_left(x, y)
                        if self.stop_event.wait(wait_ms / 1000):
                            break

                        match = self._find_target_once(
                            region,  # type: ignore[arg-type]
                            target,  # type: ignore[arg-type]
                            tolerance,
                            step,
                        )
                        if match:
                            self._handle_routine_match(
                                match,
                                post_points,
                                post_delay,
                                auto_click_on_match,
                                run_post_points,
                                confirm_selection,
                                confirm_wait,
                            )
                            return
                else:
                    self.root.after(
                        0,
                        self.status_var.set,
                        f"보조 실행 중: {scan_area} 안에서 대상 색상을 탐지 중입니다.",
                    )

                cycles += 1
                if max_cycles and cycles >= max_cycles:
                    self.last_finish_message = (
                        f"보조 실행 정지: 최대 반복 {max_cycles}회 안에 대상 색상을 찾지 못했습니다."
                    )
                    self.stop_event.set()
                    break
                if self.stop_event.wait(max(0.02, cycle_delay)):
                    break

            if self.last_finish_message == "보조 실행이 정지되었습니다.":
                self.last_finish_message = "보조 실행이 사용자 요청으로 정지되었습니다."
        except Exception as exc:
            self.last_finish_message = f"보조 실행 오류: {exc}"
            self.root.after(0, messagebox.showerror, "보조 실행 오류", str(exc))
        finally:
            self.root.after(0, self._scan_finished)

    def _handle_routine_match(
        self,
        match: tuple[int, int, tuple[int, int, int]],
        post_points: list[tuple[int, int]],
        post_delay: float,
        auto_click_on_match: bool,
        run_post_points: bool,
        confirm_selection: bool,
        confirm_wait_ms: int,
    ) -> None:
        x, y, found_rgb = match
        self.screen.move_mouse(x, y)
        if not auto_click_on_match:
            self.last_finish_message = (
                f"보조 실행 완료: 대상 색상을 ({x}, {y})에서 찾고 마우스 커서만 이동했습니다. "
                "자동 클릭은 실행하지 않았습니다."
            )
            self.root.after(0, self.status_var.set, self.last_finish_message)
            self.stop_event.set()
            return

        before_patch = b""
        if confirm_selection:
            before_patch, _left, _top, _width, _height = self._capture_click_patch(x, y)

        self.root.after(
            0,
            self.status_var.set,
            f"대상 색상 발견: ({x}, {y}) RGB {found_rgb[0]}, {found_rgb[1]}, {found_rgb[2]} 자동 클릭 중",
        )
        self.screen.click_left(x, y)

        if confirm_selection:
            self.root.after(
                0,
                self.status_var.set,
                "자동 클릭 후 화면 변화 하드 판단 중입니다.",
            )
            confirmed, details = self._wait_for_click_confirmation(
                x,
                y,
                before_patch,
                confirm_wait_ms,
            )
            if not confirmed:
                self.last_finish_message = (
                    "자동 클릭 후 화면 변화가 확인되지 않아 발견 후 보조 좌표를 실행하지 않았습니다. "
                    f"하드 판단값: {details}"
                )
                self.stop_event.set()
                return
            self.root.after(
                0,
                self.status_var.set,
                f"선택 변화 확인 완료: {details}",
            )

        if post_points and not run_post_points:
            self.last_finish_message = (
                f"보조 실행 완료: 대상 색상을 ({x}, {y})에서 클릭했습니다. "
                "발견 후 선택적 보조 좌표 실행 옵션이 꺼져 있어 보조 좌표는 실행하지 않았습니다."
            )
            self.stop_event.set()
            return

        if post_points and not self._confirm_post_points_from_worker(len(post_points)):
            self.last_finish_message = (
                "발견 후 선택적 보조 좌표 실행이 사용자 확인 단계에서 취소되었습니다."
            )
            self.stop_event.set()
            return

        for index, (post_x, post_y) in enumerate(post_points, start=1):
            if self.stop_event.wait(post_delay):
                self.last_finish_message = "보조 실행이 발견 후 보조 좌표 실행 중 정지되었습니다."
                return
            self.root.after(
                0,
                self.status_var.set,
                f"발견 후 선택적 보조 좌표 실행 중: {index}/{len(post_points)} 클릭 x={post_x}, y={post_y}",
            )
            self.screen.click_left(post_x, post_y)

        self.last_finish_message = (
            f"보조 실행 완료: 대상 색상을 ({x}, {y})에서 클릭했고 "
            f"발견 후 선택적 보조 좌표 {len(post_points)}개를 실행했습니다."
        )
        self.stop_event.set()

    def start_scan(self) -> None:
        if self.scan_thread and self.scan_thread.is_alive():
            return

        if self.eyedropper_active:
            self._finish_eyedropper(keep=False)

        if self.region_overlay:
            self._finish_region_selection(update_status=False)
        if self.point_picker_overlay:
            self._finish_point_picker(update_status=False)

        try:
            config = {
                "target": self.target_color,
                "tolerance": self._read_int_var(
                    self.tolerance_var, "허용 오차", 0, 80
                ),
                "step": self._read_int_var(self.step_var, "스캔 촘촘함", 1, 20),
                "interval": self._read_int_var(
                    self.interval_var, "스캔 간격", MIN_SCAN_INTERVAL_MS, 2000
                ),
                "stop_on_first": bool(self.stop_on_first_var.get()),
                "region": self.scan_region,
            }
        except ValueError as exc:
            messagebox.showerror("탐지 설정 오류", str(exc), parent=self.root)
            return

        self.stop_event.clear()
        self.last_finish_message = "탐지가 정지되었습니다."
        self.start_button.configure(state=tk.DISABLED)
        self.stop_button.configure(state=tk.NORMAL)
        self.routine_start_button.configure(state=tk.DISABLED)
        self.status_var.set(
            "탐지 중입니다. "
            f"{format_region(self.scan_region)} 안에서 일치하는 색상을 찾으면 "
            "마우스 커서만 해당 위치로 이동합니다."
        )

        self.scan_thread = threading.Thread(
            target=self._scan_loop, args=(config,), daemon=True
        )
        self.scan_thread.start()

    def stop_scan(self) -> None:
        self.stop_event.set()
        if self.scan_thread and self.scan_thread.is_alive():
            self.status_var.set("정지 요청 중입니다.")

    def _scan_loop(self, config: dict[str, object]) -> None:
        target = config["target"]
        tolerance = int(config["tolerance"])
        step = int(config["step"])
        interval = int(config["interval"]) / 1000
        stop_on_first = bool(config["stop_on_first"])
        region = config["region"]
        scan_area = format_region(region)  # type: ignore[arg-type]

        try:
            while not self.stop_event.is_set():
                started_at = time.perf_counter()
                match = self._find_target_once(
                    region,  # type: ignore[arg-type]
                    target,  # type: ignore[arg-type]
                    tolerance,
                    step,
                )

                if match:
                    x, y, found_rgb = match
                    self.screen.move_mouse(x, y)
                    self.last_finish_message = (
                        f"탐지 완료: ({x}, {y}) 위치에서 RGB "
                        f"{found_rgb[0]}, {found_rgb[1]}, {found_rgb[2]} 색상을 찾고 커서만 이동했습니다."
                    )
                    self.root.after(0, self.status_var.set, self.last_finish_message)
                    if stop_on_first:
                        self.stop_event.set()
                        break
                else:
                    self.root.after(
                        0,
                        self.status_var.set,
                        f"탐지 중입니다. {scan_area} 안에서 아직 일치하는 색상을 찾지 못했습니다.",
                    )

                elapsed = time.perf_counter() - started_at
                self.stop_event.wait(max(0.01, interval - elapsed))
        except Exception as exc:
            self.last_finish_message = f"탐지 오류: {exc}"
            self.root.after(0, messagebox.showerror, "탐지 오류", str(exc))
        finally:
            self.root.after(0, self._scan_finished)

    def _scan_finished(self) -> None:
        self.start_button.configure(state=tk.NORMAL)
        self.stop_button.configure(state=tk.DISABLED)
        self.routine_start_button.configure(state=tk.NORMAL)
        self.status_var.set(self.last_finish_message)


def smoke_test() -> str:
    screen = WindowsScreen()
    x, y = screen.cursor_position()
    rgb = screen.pixel_at(x, y)
    data, left, top, width, height = screen.capture_screen()
    region_width = min(64, width)
    region_height = min(64, height)
    region_data, region_left, region_top, _, _ = screen.capture_region(
        left, top, region_width, region_height
    )

    sample = bytes(
        [
            120,
            110,
            100,
            0,
            30,
            20,
            10,
            0,
        ]
    )
    found = find_matching_pixel(sample, 2, 1, 10, 20, (100, 110, 120), 0, 1)
    if found != (10, 20, (100, 110, 120)):
        raise RuntimeError("색상 탐지 테스트에 실패했습니다.")

    if len(data) != width * height * 4:
        raise RuntimeError("화면 캡처 크기 테스트에 실패했습니다.")
    if len(region_data) != region_width * region_height * 4:
        raise RuntimeError("부분 화면 캡처 크기 테스트에 실패했습니다.")
    if (region_left, region_top) != (left, top):
        raise RuntimeError("부분 화면 캡처 좌표 테스트에 실패했습니다.")

    return (
        f"OK cursor=({x}, {y}) rgb=({rgb[0]}, {rgb[1]}, {rgb[2]}) "
        f"capture=({left}, {top}, {width}, {height}) "
        f"region=({region_left}, {region_top}, {region_width}, {region_height})"
    )


def main() -> None:
    if "--smoke-test" in sys.argv:
        print(smoke_test())
        return

    root = tk.Tk()
    try:
        LocalPixelMouseAssistantApp(root)
    except Exception as exc:
        messagebox.showerror("실행 오류", str(exc), parent=root)
        root.destroy()
        return
    root.mainloop()


if __name__ == "__main__":
    main()
