from __future__ import annotations

import math
import shutil
import struct
import threading
import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, ttk


JPEG_EXTENSIONS = {".jpg", ".jpeg"}
APP1_MARKER = b"\xFF\xE1"
SOI_MARKER = b"\xFF\xD8"
FLIR_MAGIC = b"FLIR\x00"
FLIR_CHUNK_MAGIC = b"FLIR"
CAMERA_INFO_RECORD_TYPE = 0x20


@dataclass(frozen=True)
class CameraInfoOffsets:
    emissivity: int = 0x20
    distance: int = 0x24
    reflected_temp: int = 0x28
    atmospheric_temp: int = 0x2C
    ext_optics_temp: int = 0x30
    ext_optics_trans: int = 0x34
    relative_humidity: int = 0x3C


CAMERA_INFO_OFFSETS = CameraInfoOffsets()


class FlirPatchError(Exception):
    pass


@dataclass
class PatchValues:
    emissivity: float | None
    reflected_temp_c: float | None
    distance_m: float | None
    atmospheric_temp_c: float | None
    ext_optics_temp_c: float | None
    ext_optics_trans: float | None
    relative_humidity_percent: float | None


@dataclass
class FileResult:
    path: Path
    success: bool
    message: str


@dataclass
class InspectionData:
    emissivity: float
    reflected_temp_c: float
    distance_m: float
    atmospheric_temp_c: float
    ext_optics_temp_c: float
    ext_optics_trans: float
    relative_humidity_percent: float


@dataclass
class FlirChunk:
    payload_start: int
    payload_end: int
    data_offset: int
    data_length: int


def read_u16_be(data: bytes, offset: int) -> int:
    return struct.unpack_from(">H", data, offset)[0]


def read_u32(data: bytes, offset: int, byte_order: str) -> int:
    fmt = "<I" if byte_order == "little" else ">I"
    return struct.unpack_from(fmt, data, offset)[0]


def read_u16(data: bytes, offset: int, byte_order: str) -> int:
    fmt = "<H" if byte_order == "little" else ">H"
    return struct.unpack_from(fmt, data, offset)[0]


def read_f32(data: bytes, offset: int, byte_order: str) -> float:
    fmt = "<f" if byte_order == "little" else ">f"
    return struct.unpack_from(fmt, data, offset)[0]


def write_f32(buffer: bytearray, offset: int, value: float, byte_order: str) -> None:
    fmt = "<f" if byte_order == "little" else ">f"
    struct.pack_into(fmt, buffer, offset, value)


def celsius_to_kelvin(value_c: float) -> float:
    return value_c + 273.15


def detect_camera_info_byte_order(record_data: bytes) -> str:
    if len(record_data) < 2:
        raise FlirPatchError("CameraInfo record is too short.")

    first_be = struct.unpack_from(">H", record_data, 0)[0]
    first_le = struct.unpack_from("<H", record_data, 0)[0]

    if first_be == 2:
        return "big"
    if first_le == 2:
        return "little"

    width_be = struct.unpack_from(">H", record_data, 2)[0] if len(record_data) >= 4 else 0
    width_le = struct.unpack_from("<H", record_data, 2)[0] if len(record_data) >= 4 else 0
    if 1 <= width_be <= 10000:
        return "big"
    if 1 <= width_le <= 10000:
        return "little"

    raise FlirPatchError("Unable to determine CameraInfo byte order.")


def iter_flir_app1_segments(data: bytes):
    if len(data) < 4 or data[:2] != SOI_MARKER:
        raise FlirPatchError("Not a JPEG file.")

    pos = 2
    data_len = len(data)
    while pos + 4 <= data_len:
        if data[pos] != 0xFF:
            break

        marker = data[pos : pos + 2]
        pos += 2

        if marker == b"\xFF\xD9" or marker == b"\xFF\xDA":
            break

        if pos + 2 > data_len:
            break

        segment_len = read_u16_be(data, pos)
        segment_start = pos - 2
        payload_start = pos + 2
        payload_end = payload_start + segment_len - 2
        if payload_end > data_len:
            raise FlirPatchError("JPEG segment length exceeds file size.")

        if marker == APP1_MARKER and data[payload_start:payload_start + 4] == FLIR_CHUNK_MAGIC:
            yield segment_start, payload_start, payload_end

        pos = payload_end


def iter_flir_payloads(data: bytes):
    current_chunks: list[FlirChunk] = []
    current_bytes = bytearray()

    for _, payload_start, payload_end in iter_flir_app1_segments(data):
        payload = data[payload_start:payload_end]
        prefix4 = bytes(payload[:4])
        if prefix4 == b"FFF\x00" or prefix4 == b"AFF\x00":
            chunk_data_offset = 0
        elif len(payload) >= 8 and prefix4 == FLIR_CHUNK_MAGIC:
            chunk_data_offset = 8
        else:
            continue
        chunk_payload = payload[chunk_data_offset:]

        current_chunks.append(
            FlirChunk(
                payload_start=payload_start,
                payload_end=payload_end,
                data_offset=chunk_data_offset,
                data_length=len(chunk_payload),
            )
        )
        current_bytes.extend(chunk_payload)

    if current_chunks:
        yield bytes(current_bytes), current_chunks


def write_combined_slice(
    file_bytes: bytearray,
    chunks: list[FlirChunk],
    combined_offset: int,
    new_data: bytes,
) -> None:
    remaining = memoryview(new_data)
    current_offset = combined_offset

    for chunk in chunks:
        if current_offset >= chunk.data_length:
            current_offset -= chunk.data_length
            continue

        writable = min(len(remaining), chunk.data_length - current_offset)
        file_start = chunk.payload_start + chunk.data_offset + current_offset
        file_end = file_start + writable
        file_bytes[file_start:file_end] = remaining[:writable]
        remaining = remaining[writable:]
        current_offset = 0

        if not remaining:
            return

    if remaining:
        raise FlirPatchError("Patched FLIR record spans beyond available APP1 chunks.")


def parse_flir_record_directory(payload: bytes):
    if len(payload) < 0x40:
        raise FlirPatchError("FLIR APP1 segment is too short.")

    header = payload[:0x40]
    if not (header.startswith(b"FFF\x00") or header.startswith(b"AFF\x00")):
        raise FlirPatchError("FLIR FFF/AFF header is missing.")

    version_be = struct.unpack_from(">I", header, 0x14)[0]
    version_le = struct.unpack_from("<I", header, 0x14)[0]

    if 100 <= version_be < 200:
        directory_order = "big"
    elif 100 <= version_le < 200:
        directory_order = "little"
    else:
        raise FlirPatchError("Unsupported FLIR header version.")

    dir_offset = read_u32(header, 0x18, directory_order)
    dir_count = read_u32(header, 0x1C, directory_order)
    directory_size = dir_count * 0x20
    dir_end = dir_offset + directory_size

    if dir_end > len(payload):
        raise FlirPatchError("FLIR record directory exceeds payload size.")

    records = []
    for idx in range(dir_count):
        entry_offset = dir_offset + idx * 0x20
        record_type = read_u16(payload, entry_offset, directory_order)
        if record_type == 0:
            continue

        record_offset = read_u32(payload, entry_offset + 0x0C, directory_order)
        record_length = read_u32(payload, entry_offset + 0x10, directory_order)
        if record_offset + record_length > len(payload):
            raise FlirPatchError("FLIR record exceeds payload size.")

        records.append((record_type, record_offset, record_length))

    return records


def patch_camera_info_record(record_data: bytearray, values: PatchValues) -> None:
    byte_order = detect_camera_info_byte_order(record_data)

    updates: dict[int, float] = {}
    if values.emissivity is not None:
        updates[CAMERA_INFO_OFFSETS.emissivity] = values.emissivity
    if values.distance_m is not None:
        updates[CAMERA_INFO_OFFSETS.distance] = values.distance_m
    if values.reflected_temp_c is not None:
        updates[CAMERA_INFO_OFFSETS.reflected_temp] = celsius_to_kelvin(values.reflected_temp_c)
    if values.atmospheric_temp_c is not None:
        updates[CAMERA_INFO_OFFSETS.atmospheric_temp] = celsius_to_kelvin(values.atmospheric_temp_c)
    if values.ext_optics_temp_c is not None:
        updates[CAMERA_INFO_OFFSETS.ext_optics_temp] = celsius_to_kelvin(values.ext_optics_temp_c)
    if values.ext_optics_trans is not None:
        updates[CAMERA_INFO_OFFSETS.ext_optics_trans] = values.ext_optics_trans
    if values.relative_humidity_percent is not None:
        updates[CAMERA_INFO_OFFSETS.relative_humidity] = values.relative_humidity_percent / 100.0

    for offset, number in updates.items():
        if offset + 4 > len(record_data):
            raise FlirPatchError("CameraInfo record is missing expected fields.")
        if not math.isfinite(number):
            raise FlirPatchError("Encountered a non-finite value while patching.")
        write_f32(record_data, offset, float(number), byte_order)


def format_inspection(data: InspectionData) -> str:
    return (
        f"E={data.emissivity:.3f}, Refl={data.reflected_temp_c:.2f} C, Dist={data.distance_m:.2f} m, "
        f"Atm={data.atmospheric_temp_c:.2f} C, Optics={data.ext_optics_temp_c:.2f} C, "
        f"Trans={data.ext_optics_trans:.3f}, RH={data.relative_humidity_percent:.1f}%"
    )


def inspect_flir_file(path: Path) -> InspectionData:
    data = path.read_bytes()
    for payload, _chunks in iter_flir_payloads(data):
        for record_type, record_offset, record_length in parse_flir_record_directory(payload):
            if record_type == CAMERA_INFO_RECORD_TYPE:
                record = payload[record_offset:record_offset + record_length]
                order = detect_camera_info_byte_order(record)
                return InspectionData(
                    emissivity=read_f32(record, CAMERA_INFO_OFFSETS.emissivity, order),
                    reflected_temp_c=read_f32(record, CAMERA_INFO_OFFSETS.reflected_temp, order) - 273.15,
                    distance_m=read_f32(record, CAMERA_INFO_OFFSETS.distance, order),
                    atmospheric_temp_c=read_f32(record, CAMERA_INFO_OFFSETS.atmospheric_temp, order) - 273.15,
                    ext_optics_temp_c=read_f32(record, CAMERA_INFO_OFFSETS.ext_optics_temp, order) - 273.15,
                    ext_optics_trans=read_f32(record, CAMERA_INFO_OFFSETS.ext_optics_trans, order),
                    relative_humidity_percent=read_f32(record, CAMERA_INFO_OFFSETS.relative_humidity, order) * 100.0,
                )
    raise FlirPatchError("No writable FLIR CameraInfo record was found.")


def patch_flir_file(path: Path, values: PatchValues, create_backup: bool = True) -> None:
    data = bytearray(path.read_bytes())

    if create_backup:
        backup_path = path.with_suffix(path.suffix + ".bak")
        if not backup_path.exists():
            shutil.copy2(path, backup_path)

    patched = False
    for payload, chunks in iter_flir_payloads(data):
        records = parse_flir_record_directory(payload)
        for record_type, record_offset, record_length in records:
            if record_type != CAMERA_INFO_RECORD_TYPE:
                continue

            record_data = bytearray(payload[record_offset:record_offset + record_length])
            patch_camera_info_record(record_data, values)
            write_combined_slice(data, chunks, record_offset, record_data)
            patched = True

    if not patched:
        raise FlirPatchError("No FLIR CameraInfo record was found.")

    path.write_bytes(data)


class App:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("FLIR Batch Parameter Editor")
        self.root.geometry("1360x860")
        self.root.minsize(1120, 760)

        self.selected_paths: list[Path] = []
        self.file_state: dict[Path, tuple[bool, str]] = {}
        self.file_check_vars: dict[Path, tk.BooleanVar] = {}
        self.file_name_buttons: dict[Path, ttk.Button] = {}
        self.file_inspections: dict[Path, InspectionData] = {}
        self.preview_path: Path | None = None

        self.emissivity_var = tk.StringVar(value="0.98")
        self.reflected_var = tk.StringVar(value="")
        self.distance_var = tk.StringVar(value="")
        self.atmospheric_var = tk.StringVar(value="")
        self.ext_optics_temp_var = tk.StringVar(value="")
        self.ext_optics_trans_var = tk.StringVar(value="")
        self.relative_humidity_var = tk.StringVar(value="")
        self.folder_var = tk.StringVar()
        self.backup_var = tk.BooleanVar(value=True)
        self.selection_status_var = tk.StringVar(value="Choose files, tick the targets, click a filename to preview, then execute the values on the right.")
        self.preview_file_var = tk.StringVar(value="No preview file selected")
        self.preview_status_var = tk.StringVar(value="Click a file name on the left to preview its current FLIR values.")
        self.preview_summary_var = tk.StringVar(value="No preview loaded yet.")
        self.form_status_var = tk.StringVar(value="Batch values: Ready")
        self.target_summary_var = tk.StringVar(value="Target files: 0")
        self.activity_visible_var = tk.BooleanVar(value=False)
        self.preview_values: InspectionData | None = None
        self.suspend_form_tracking = False
        self.activity_window: tk.Toplevel | None = None
        self.activity_text: tk.Text | None = None

        self._configure_styles()
        self.root.protocol("WM_DELETE_WINDOW", self.close_app)
        self._build_ui()
        self._wire_form_tracking()

    def _configure_styles(self) -> None:
        style = ttk.Style()
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Header.TLabel", font=("Segoe UI", 12, "bold"))
        style.configure("Subtle.TLabel", foreground="#5f6b7a")
        style.configure("Card.TLabelframe", padding=12)
        style.configure("Card.TLabelframe.Label", font=("Segoe UI", 11, "bold"))
        style.configure("Action.TButton", padding=(10, 8))
        style.configure("FileRow.TButton", anchor="w", padding=(10, 8))

    def _build_ui(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)

        header = ttk.Frame(self.root, padding=12)
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(1, weight=1)

        ttk.Label(
            header,
            text="Batch edit FLIR radiometric JPEG parameters",
            font=("Segoe UI", 16, "bold"),
        ).grid(row=0, column=0, columnspan=3, sticky="w")

        ttk.Label(
            header,
            text="Works on JPEG files that contain a FLIR CameraInfo record. Unsupported files are skipped safely.",
            wraplength=900,
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(4, 0))

        body = ttk.Panedwindow(self.root, orient=tk.HORIZONTAL)
        body.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))

        left = ttk.LabelFrame(body, text="Selection", style="Card.TLabelframe")
        right = ttk.LabelFrame(body, text="Batch Values", style="Card.TLabelframe")
        body.add(left, weight=3)
        body.add(right, weight=2)

        left.columnconfigure(0, weight=1)
        left.rowconfigure(3, weight=1)
        right.columnconfigure(1, weight=1)

        controls = ttk.Frame(left)
        controls.grid(row=0, column=0, sticky="ew", pady=(4, 10))
        for idx in range(4):
            controls.columnconfigure(idx, weight=1)

        ttk.Button(controls, text="Choose Folder", command=self.choose_folder, style="Action.TButton").grid(row=0, column=0, padx=(0, 6), sticky="ew")
        ttk.Button(controls, text="Choose Files", command=self.choose_files, style="Action.TButton").grid(row=0, column=1, padx=6, sticky="ew")
        ttk.Button(controls, text="Select All", command=self.select_all_files, style="Action.TButton").grid(row=0, column=2, padx=6, sticky="ew")
        ttk.Button(controls, text="Select None", command=self.select_no_files, style="Action.TButton").grid(row=0, column=3, padx=(6, 0), sticky="ew")

        ttk.Label(left, textvariable=self.folder_var, style="Subtle.TLabel").grid(row=1, column=0, sticky="w", pady=(0, 8))

        list_frame = ttk.Frame(left)
        list_frame.grid(row=2, column=0, sticky="nsew")
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)

        self.file_canvas = tk.Canvas(list_frame, highlightthickness=1, highlightbackground="#d9dde3")
        self.file_canvas.grid(row=0, column=0, sticky="nsew")
        list_scroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.file_canvas.yview)
        list_scroll.grid(row=0, column=1, sticky="ns")
        self.file_canvas.configure(yscrollcommand=list_scroll.set)
        self.file_rows_frame = ttk.Frame(self.file_canvas)
        self.file_rows_frame.columnconfigure(1, weight=1)
        self.file_canvas_window = self.file_canvas.create_window((0, 0), window=self.file_rows_frame, anchor="nw")
        self.file_rows_frame.bind("<Configure>", self.on_file_rows_configure)
        self.file_canvas.bind("<Configure>", self.on_file_canvas_configure)

        action_bar = ttk.Frame(left)
        action_bar.grid(row=3, column=0, sticky="ew", pady=(12, 0))
        action_bar.columnconfigure(0, weight=1)
        action_bar.columnconfigure(1, weight=1)
        action_bar.columnconfigure(2, weight=1)
        ttk.Button(action_bar, text="Invert Ticks", command=self.invert_file_selection, style="Action.TButton").grid(row=0, column=0, padx=(0, 6), sticky="ew")
        ttk.Button(action_bar, text="Remove Ticked", command=self.remove_selected, style="Action.TButton").grid(row=0, column=1, padx=6, sticky="ew")
        ttk.Button(action_bar, text="Clear List", command=self.clear_files, style="Action.TButton").grid(row=0, column=2, padx=(6, 0), sticky="ew")
        ttk.Button(action_bar, text="Execute Batch Changes", command=self.apply_changes, style="Action.TButton").grid(row=1, column=0, columnspan=2, padx=(0, 6), pady=(8, 0), sticky="ew")
        ttk.Checkbutton(action_bar, text="Create .bak backups", variable=self.backup_var).grid(row=1, column=2, padx=(6, 0), pady=(8, 0), sticky="e")
        ttk.Label(left, textvariable=self.selection_status_var, style="Subtle.TLabel", wraplength=620).grid(row=4, column=0, sticky="w", pady=(10, 0))
        ttk.Label(left, textvariable=self.target_summary_var, style="Subtle.TLabel", wraplength=620).grid(row=5, column=0, sticky="w", pady=(4, 0))

        preview_frame = ttk.LabelFrame(right, text="Preview", style="Card.TLabelframe")
        preview_frame.grid(row=0, column=0, columnspan=3, sticky="ew")
        preview_frame.columnconfigure(1, weight=1)
        ttk.Label(preview_frame, text="File").grid(row=0, column=0, sticky="nw", pady=(0, 6))
        ttk.Label(preview_frame, textvariable=self.preview_file_var, wraplength=460).grid(row=0, column=1, sticky="w", pady=(0, 6))
        ttk.Label(preview_frame, text="Status").grid(row=1, column=0, sticky="nw", pady=(0, 6))
        ttk.Label(preview_frame, textvariable=self.preview_status_var, wraplength=460).grid(row=1, column=1, sticky="w", pady=(0, 6))
        ttk.Label(preview_frame, text="Values").grid(row=2, column=0, sticky="nw")
        ttk.Label(preview_frame, textvariable=self.preview_summary_var, wraplength=460, justify="left").grid(row=2, column=1, sticky="w")
        ttk.Button(preview_frame, text="Copy Preview To Form", command=self.copy_preview_to_form, style="Action.TButton").grid(row=3, column=1, sticky="w", pady=(10, 0))

        form_header = ttk.Frame(right)
        form_header.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(12, 6))
        form_header.columnconfigure(1, weight=1)
        ttk.Label(form_header, text="Batch Form", style="Header.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(form_header, textvariable=self.form_status_var, style="Subtle.TLabel", wraplength=440).grid(row=0, column=1, sticky="e")

        fields = [
            ("Emissivity", self.emissivity_var, "0.01 to 1.00"),
            ("Refl. temp. (C)", self.reflected_var, "Celsius"),
            ("Distance (m)", self.distance_var, "meters"),
            ("Atmospheric temp. (C)", self.atmospheric_var, "Celsius"),
            ("Ext. optics temp. (C)", self.ext_optics_temp_var, "Celsius"),
            ("Ext. optics trans.", self.ext_optics_trans_var, "0.00 to 1.00"),
            ("Relative humidity (%)", self.relative_humidity_var, "0 to 100"),
        ]

        form_fields = ttk.Frame(right)
        form_fields.grid(row=2, column=0, columnspan=3, sticky="ew")
        form_fields.columnconfigure(1, weight=1)
        for row, (label_text, variable, hint) in enumerate(fields):
            ttk.Label(form_fields, text=label_text).grid(row=row, column=0, sticky="w", pady=6)
            entry = ttk.Entry(form_fields, textvariable=variable)
            entry.grid(row=row, column=1, sticky="ew", pady=6, padx=(10, 0))
            ttk.Label(form_fields, text=hint, style="Subtle.TLabel").grid(row=row, column=2, sticky="w", padx=(10, 0), pady=6)

        footer_bar = ttk.Frame(right)
        footer_bar.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(12, 0))
        footer_bar.columnconfigure(0, weight=1)
        ttk.Label(
            footer_bar,
            text="Workflow: tick files, preview one if needed, adjust the batch form, then execute. Leave a field blank to keep its current value.",
            style="Subtle.TLabel",
            wraplength=420,
        ).grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(
            footer_bar,
            text="Show Activity",
            variable=self.activity_visible_var,
            command=self.toggle_activity,
        ).grid(row=0, column=1, sticky="e")

        self.log_box = tk.Text(right, height=1, wrap="word")
        self.log_box.configure(state="disabled")
        self.toggle_activity()

    def log(self, message: str) -> None:
        self.log_box.configure(state="normal")
        self.log_box.insert("end", message.rstrip() + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")
        if self.activity_text is not None:
            self.activity_text.configure(state="normal")
            self.activity_text.insert("end", message.rstrip() + "\n")
            self.activity_text.see("end")
            self.activity_text.configure(state="disabled")

    def toggle_activity(self) -> None:
        if self.activity_visible_var.get():
            if self.activity_window is None or not self.activity_window.winfo_exists():
                self.activity_window = tk.Toplevel(self.root)
                self.activity_window.title("FLIR Activity")
                self.activity_window.geometry("720x320")
                self.activity_window.minsize(520, 220)
                self.activity_window.protocol("WM_DELETE_WINDOW", self.close_activity_window)
                frame = ttk.Frame(self.activity_window, padding=12)
                frame.grid(row=0, column=0, sticky="nsew")
                self.activity_window.columnconfigure(0, weight=1)
                self.activity_window.rowconfigure(0, weight=1)
                frame.columnconfigure(0, weight=1)
                frame.rowconfigure(0, weight=1)
                self.activity_text = tk.Text(frame, wrap="word")
                self.activity_text.grid(row=0, column=0, sticky="nsew")
                scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.activity_text.yview)
                scroll.grid(row=0, column=1, sticky="ns")
                self.activity_text.configure(yscrollcommand=scroll.set, state="disabled")
                existing = self.log_box.get("1.0", "end-1c")
                if existing:
                    self.activity_text.configure(state="normal")
                    self.activity_text.insert("end", existing)
                    self.activity_text.see("end")
                    self.activity_text.configure(state="disabled")
            else:
                self.activity_window.deiconify()
                self.activity_window.lift()
        else:
            self.close_activity_window()

    def close_activity_window(self) -> None:
        self.activity_visible_var.set(False)
        if self.activity_window is not None and self.activity_window.winfo_exists():
            self.activity_window.destroy()
        self.activity_window = None
        self.activity_text = None

    def close_app(self) -> None:
        if self.activity_window is not None and self.activity_window.winfo_exists():
            self.activity_window.destroy()
        self.activity_window = None
        self.activity_text = None
        self.root.destroy()

    def _wire_form_tracking(self) -> None:
        for variable in (
            self.emissivity_var,
            self.reflected_var,
            self.distance_var,
            self.atmospheric_var,
            self.ext_optics_temp_var,
            self.ext_optics_trans_var,
            self.relative_humidity_var,
        ):
            variable.trace_add("write", self.on_form_changed)

    def on_form_changed(self, *_args) -> None:
        if self.suspend_form_tracking:
            return
        if self.preview_values is None:
            self.form_status_var.set("Batch values: Ready")
            return
        try:
            current = self.collect_values()
        except FlirPatchError:
            self.form_status_var.set("Batch values: Editing draft")
            return
        loaded = self.preview_values
        matches = (
            abs(current.emissivity - loaded.emissivity) < 1e-6
            and abs(current.reflected_temp_c - loaded.reflected_temp_c) < 1e-6
            and abs(current.distance_m - loaded.distance_m) < 1e-6
            and abs(current.atmospheric_temp_c - loaded.atmospheric_temp_c) < 1e-6
            and abs(current.ext_optics_temp_c - loaded.ext_optics_temp_c) < 1e-6
            and abs(current.ext_optics_trans - loaded.ext_optics_trans) < 1e-6
            and abs(current.relative_humidity_percent - loaded.relative_humidity_percent) < 1e-6
        )
        self.form_status_var.set("Batch values: Match preview file" if matches else "Batch values: Edited draft ready to apply")

    def on_file_rows_configure(self, _event=None) -> None:
        self.file_canvas.configure(scrollregion=self.file_canvas.bbox("all"))

    def on_file_canvas_configure(self, event=None) -> None:
        self.file_canvas.itemconfigure(self.file_canvas_window, width=event.width)

    def refresh_file_rows(self) -> None:
        for child in self.file_rows_frame.winfo_children():
            child.destroy()
        self.file_check_vars.clear()
        self.file_name_buttons.clear()

        for row, path in enumerate(self.selected_paths):
            check_var = tk.BooleanVar(value=False)
            self.file_check_vars[path] = check_var
            ttk.Checkbutton(
                self.file_rows_frame,
                variable=check_var,
                command=self.update_target_summary,
            ).grid(row=row, column=0, sticky="w", padx=(0, 6), pady=2)
            button = ttk.Button(
                self.file_rows_frame,
                text=path.name,
                command=lambda p=path: self.preview_selected_file(p),
                style="FileRow.TButton",
            )
            button.grid(row=row, column=1, sticky="ew", pady=2)
            self.file_name_buttons[path] = button

    def preview_selected_file(self, path: Path) -> None:
        self.preview_path = path
        self.preview_file_var.set(str(path))
        self.selection_status_var.set(f"Previewing: {path.name}")

        cached = self.file_inspections.get(path)
        if cached is not None:
            self._finish_preview(FileResult(path, True, format_inspection(cached)), cached)
            return

        def worker() -> None:
            try:
                details = inspect_flir_file(path)
                result = FileResult(path, True, format_inspection(details))
                self.root.after(0, lambda: self._finish_preview(result, details))
            except Exception as exc:
                result = FileResult(path, False, str(exc))
                self.root.after(0, lambda: self._finish_preview(result, None))

        threading.Thread(target=worker, daemon=True).start()

    def _finish_preview(self, result: FileResult, details: InspectionData | None) -> None:
        self.file_state[result.path] = (result.success, result.message)
        if result.success and details is not None:
            self.file_inspections[result.path] = details
            self.preview_values = details
            self.preview_status_var.set("Preview loaded")
            self.preview_summary_var.set(result.message)
            self.selection_status_var.set(f"Preview loaded from {result.path.name}.")
        else:
            self.preview_values = None
            self.preview_status_var.set(result.message)
            self.preview_summary_var.set("Preview unavailable.")
            self.selection_status_var.set(f"Preview failed for {result.path.name}.")

    def copy_preview_to_form(self) -> None:
        if self.preview_values is None:
            messagebox.showinfo("No preview", "Preview a file first.")
            return
        self.load_values_into_form(self.preview_values)
        self.form_status_var.set("Batch values: Copied from preview")

    def load_values_into_form(self, details: InspectionData) -> None:
        self.suspend_form_tracking = True
        self.emissivity_var.set(f"{details.emissivity:.3f}")
        self.reflected_var.set(f"{details.reflected_temp_c:.2f}")
        self.distance_var.set(f"{details.distance_m:.2f}")
        self.atmospheric_var.set(f"{details.atmospheric_temp_c:.2f}")
        self.ext_optics_temp_var.set(f"{details.ext_optics_temp_c:.2f}")
        self.ext_optics_trans_var.set(f"{details.ext_optics_trans:.3f}")
        self.relative_humidity_var.set(f"{details.relative_humidity_percent:.1f}")
        self.suspend_form_tracking = False
        self.on_form_changed()

    def update_target_summary(self) -> None:
        count = len(self.get_checked_paths())
        total = len(self.selected_paths)
        self.target_summary_var.set(f"Target files ticked: {count} of {total}")

    def get_checked_paths(self) -> list[Path]:
        return [path for path in self.selected_paths if self.file_check_vars.get(path) and self.file_check_vars[path].get()]

    def choose_folder(self) -> None:
        folder = filedialog.askdirectory(title="Choose a folder containing FLIR JPEG files")
        if not folder:
            return

        folder_path = Path(folder)
        files = sorted(
            path for path in folder_path.iterdir()
            if path.is_file() and path.suffix.lower() in JPEG_EXTENSIONS
        )
        self.folder_var.set(f"Folder loaded: {folder_path} ({len(files)} files)")
        self.set_files(files)
        self.log(f"Loaded {len(files)} JPEG files from {folder_path}")

    def choose_files(self) -> None:
        file_paths = filedialog.askopenfilenames(
            title="Choose FLIR JPEG files",
            filetypes=[("JPEG files", "*.jpg *.jpeg"), ("All files", "*.*")],
        )
        if not file_paths:
            return

        files = [Path(path) for path in file_paths]
        self.folder_var.set(f"Files loaded: {len(files)}")
        self.set_files(files)
        self.log(f"Loaded {len(files)} selected files.")

    def set_files(self, files: list[Path]) -> None:
        unique_in_order = list(dict.fromkeys(Path(path) for path in files))
        self.selected_paths = unique_in_order
        self.file_state = {path: (False, "Not inspected") for path in self.selected_paths}
        self.file_inspections = {path: details for path, details in self.file_inspections.items() if path in self.selected_paths}
        self.refresh_file_rows()
        if self.selected_paths:
            self.preview_path = self.selected_paths[0]
            self.preview_file_var.set(str(self.selected_paths[0]))
            self.preview_status_var.set("Not previewed yet")
        else:
            self.preview_path = None
            self.preview_file_var.set("No preview file selected")
            self.preview_status_var.set("Click a file name on the left to preview its current FLIR values.")
            self.preview_summary_var.set("No preview loaded yet.")
        self.update_target_summary()

    def remove_selected(self) -> None:
        selected_paths = set(self.get_checked_paths())
        if not selected_paths:
            return

        remaining = [path for path in self.selected_paths if path not in selected_paths]
        self.set_files(remaining)
        self.log(f"Removed {len(selected_paths)} file(s) from the list.")

    def clear_files(self) -> None:
        self.selected_paths = []
        self.file_state.clear()
        self.refresh_file_rows()
        self.folder_var.set("")
        self.log("Cleared the file list.")
        self.selection_status_var.set("Choose files, tick the targets, click a filename to preview, then execute the values on the right.")
        self.preview_path = None
        self.preview_values = None
        self.file_inspections.clear()
        self.preview_file_var.set("No preview file selected")
        self.preview_status_var.set("Click a file name on the left to preview its current FLIR values.")
        self.preview_summary_var.set("No preview loaded yet.")
        self.form_status_var.set("Batch values: Ready")
        self.update_target_summary()

    def collect_values(self) -> PatchValues:
        def parse_optional_number(raw: str) -> float | None:
            raw = raw.strip()
            if raw == "":
                return None
            return float(raw)

        try:
            values = PatchValues(
                emissivity=parse_optional_number(self.emissivity_var.get()),
                reflected_temp_c=parse_optional_number(self.reflected_var.get()),
                distance_m=parse_optional_number(self.distance_var.get()),
                atmospheric_temp_c=parse_optional_number(self.atmospheric_var.get()),
                ext_optics_temp_c=parse_optional_number(self.ext_optics_temp_var.get()),
                ext_optics_trans=parse_optional_number(self.ext_optics_trans_var.get()),
                relative_humidity_percent=parse_optional_number(self.relative_humidity_var.get()),
            )
        except ValueError as exc:
            raise FlirPatchError("Filled-in parameter values must be valid numbers.") from exc

        if values.emissivity is not None and not (0.01 <= values.emissivity <= 1.0):
            raise FlirPatchError("Emissivity must be between 0.01 and 1.00.")
        if values.distance_m is not None and values.distance_m < 0:
            raise FlirPatchError("Distance cannot be negative.")
        if values.ext_optics_trans is not None and not (0.0 <= values.ext_optics_trans <= 1.0):
            raise FlirPatchError("External optics transmission must be between 0.00 and 1.00.")
        if values.relative_humidity_percent is not None and not (0.0 <= values.relative_humidity_percent <= 100.0):
            raise FlirPatchError("Relative humidity must be between 0 and 100.")

        return values

    def apply_changes(self) -> None:
        files = self.get_checked_paths()
        if not files:
            messagebox.showinfo("No files selected", "Tick at least one file first.")
            return

        try:
            values = self.collect_values()
        except FlirPatchError as exc:
            messagebox.showerror("Invalid values", str(exc))
            return

        confirm = messagebox.askyesno(
            "Execute batch changes",
            f"Apply these FLIR parameters to {len(files)} file(s)?",
        )
        if not confirm:
            return

        self.log(f"Executing batch changes for {len(files)} file(s)...")

        def worker() -> None:
            results = []
            for path in files:
                try:
                    patch_flir_file(path, values, create_backup=self.backup_var.get())
                    details = inspect_flir_file(path)
                    self.file_inspections[path] = details
                    results.append(FileResult(path, True, f"Updated successfully. {format_inspection(details)}"))
                except Exception as exc:
                    results.append(FileResult(path, False, str(exc)))
            self.root.after(0, lambda: self._display_results("Execute", results))

        threading.Thread(target=worker, daemon=True).start()

    def select_all_files(self) -> None:
        for variable in self.file_check_vars.values():
            variable.set(True)
        self.update_target_summary()

    def select_no_files(self) -> None:
        for variable in self.file_check_vars.values():
            variable.set(False)
        self.update_target_summary()

    def invert_file_selection(self) -> None:
        for variable in self.file_check_vars.values():
            variable.set(not variable.get())
        self.update_target_summary()

    def _display_results(self, operation: str, results: list[FileResult]) -> None:
        success_count = sum(1 for result in results if result.success)
        failure_count = len(results) - success_count
        self.log(f"{operation} complete. Success: {success_count}, Failed: {failure_count}")
        for result in results:
            status = "OK" if result.success else "FAIL"
            self.log(f"[{status}] {result.path.name}: {result.message}")
            self.file_state[result.path] = (result.success, result.message)

        if operation == "Execute":
            self.selection_status_var.set(f"Updated {success_count} file(s). Batch form values were kept as entered.")
            self.form_status_var.set("Batch values: Draft kept after apply")

        if failure_count:
            messagebox.showwarning(
                f"{operation} finished",
                f"{success_count} file(s) succeeded and {failure_count} failed. See the log for details.",
            )
        else:
            messagebox.showinfo(f"{operation} finished", f"All {success_count} file(s) were processed successfully.")


def main() -> None:
    root = tk.Tk()
    style = ttk.Style()
    if "vista" in style.theme_names():
        style.theme_use("vista")
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
