# Reconstructed box_wrapper_cpython-39.so
# klippy/extras/box_wrapper.py
# HELLIAN | https://github.com/HELLIAN


import logging
import json
import math
import copy
import struct
import threading
import os

COLOR_MAP = {
    '000000': '黑色', '1B04AE': '深蓝', '26EEEE': '天蓝', '3DDF57': '中绿',
    '6C84FF': '钴蓝', '66DBA2': '浅绿', '72A530': '草绿', '7A92AC': '灰色',
    '8A43FF': '紫色', '9CFF4F': '嫩粉红', '9EA7AE': '深灰', 'B2A1E1': '淡紫色',
    'BA552A': '褐色', 'CE58F8': '蓝紫', 'F4E076': '浅黄', 'FF1E1E': '大红',
    'FF37AF': '粉色', 'FF614B': '橙红', 'FF8B1F': '桔黄', 'FF97E1': '嫩粉红',
    'FFA800': '中黄', 'FFF014': '柠檬黄', 'FFFFFF': '白色', '00A3FF': '蓝色',
}

# Serial protocol constants (from disassembly of packet handling code)
PACKET_HEAD = 0xAA
PACKET_TAIL = 0x55

# Command byte values
CMD_TEST           = 0x01
CMD_CREATE_CONNECT = 0x02
CMD_EXTRUDE        = 0x03
CMD_RETRUDE        = 0x04
CMD_EXTRUDE2       = 0x05
CMD_GET_BOX_STATE  = 0x10
CMD_GET_RFID       = 0x11
CMD_GET_REMAIN_LEN = 0x12
CMD_GET_HARDWARE   = 0x13
CMD_GET_VERSION    = 0x14
CMD_GET_BUFFER     = 0x15
CMD_GET_FILAMENT   = 0x16
CMD_SET_BOX_MODE   = 0x20
CMD_CTRL_MOTOR     = 0x21
CMD_TIGHTEN_UP     = 0x22
CMD_SET_PRE_LOAD   = 0x23
CMD_MEAS_WHEEL     = 0x24

# Packet field offsets (from check_rfid_valid: consts 17 and 12)
RFID_DATA_OFFSET  = 4
RFID_DATA_LEN     = 12   # 12 bytes of RFID data
RFID_TOTAL_LEN    = 17   # total packet length for RFID response
REMAIN_LEN_OFFSET = 4
MEASURING_OFFSET  = 4

# Timeouts
TIMEOUT_SHORT_TIME  = 3.0
TIMEOUT_LONG_TIME   = 10.0
TIMEOUT_LONGER_TIME = 30.0
TIMEOUT_MAX         = 60.0

# Retry count (from send_data disassembly: const 5)
MAX_SEND_RETRIES = 5

# Pre-load length (from communication_set_pre_loading: const 15)
DEFAULT_PRELOAD_LEN = 15

ERROR_KEYS = {
    'key831': 'serial_485 communication timeout',
    'key834': 'params error',
    'key835': 'extrude error, maybe blocked at connections',
    'key836': 'extrude error, maybe blockage between connections and filament sensor',
    'key837': 'extrude error, maybe blockage between filament sensor and extrusion gear',
    'key838': 'extrude error, through connections but not extruded',
    'key839': 'filament error, no filament detected at box extrude position',
    'key840': 'box switch state error',
    'key841': 'cut error, cut sensor not detected, cutting not rebound',
    'key843': 'rfid is error, get rfid: %s',
    'key844': 'the pneumatic joint is abnormal and may collapse',
    'key845': 'the nozzle is blocked',
    'key846': 'empty printing, box speed is smaller than extruder',
    'key847': 'empty printing, material enwind',
    'key848': 'material err, may break at connections',
    'key849': 'retrude error, failed to exit connections',
    'key850': 'retrude error, unspecified retrude, multiple connections triggered',
    'key851': 'retrude error, retrude but not trigger buffer empty limit',
    'key852': 'check extruder filament sensor and box sensor state',
    'key853': 'humidity sensor error',
    'key855': 'cut position error',
    'key856': 'no cutter',
    'key857': 'motor load error',
    'key858': 'errprom error',
    'key859': 'measuring wheel error',
    'key860': 'buffer error',
    'key861': 'left rfid card error',
    'key862': 'right rfid card error',
    'key863': 'retrude success but filament sensor detected',
    'key864': 'extrude but not trigger buffer full limit',
    'key865': 'retrude error, failed to exit connections',
    'key_cut_err': 'cut error',
    'key_retrude_err1': 'retrude error 1', 'key_retrude_err2': 'retrude error 2',
    'key_retrude_err3': 'retrude error 3', 'key_retrude_err4': 'retrude error 4',
    'key_retrude_err6': 'retrude error 6',
    'key_extrude_err1': 'extrude error 1', 'key_extrude_err2': 'extrude error 2',
    'key_extrude_err3': 'extrude error 3', 'key_extrude_err4': 'extrude error 4',
    'key_extrude_err5': 'extrude error 5',
    'key_filament_err': 'filament error', 'key_material_err': 'material error',
    'key_sensor_err': 'sensor error', 'key_params_err': 'params error',
    'key_state_err': 'state error', 'key_speed_err': 'speed error',
    'key_joint_err': 'joint error', 'key_timeout': 'timeout',
    'key_buffer_err': 'buffer error', 'key_cutter_err': 'cutter error',
    'key_eeprom_err': 'eeprom error', 'key_enwind_err': 'enwind error',
    'key_nozzle_blocked_err': 'nozzle blocked error',
    'key_measuring_wheel_err': 'measuring wheel error',
    'key_left_rfid_card_err': 'left rfid card error',
    'key_right_rfid_card_err': 'right rfid card error',
    'key_rfid_err': 'rfid error', 'key_load_err': 'load error',
    'key_cut_pos_err': 'cut position error',
    'key_dry_and_humidity_err': 'dry and humidity error',
}


class error(Exception):
    def __init__(self, msg):
        super().__init__(msg)
        self.msg = msg


class ParseData:
    """
    Parses raw serial data packets from the box hardware.

    Packet format (from send_data + ret_parse_process disassembly):
      [0]:      HEAD (0xAA)
      [1]:      ADDR
      [2]:      CMD
      [3..N-2]: DATA
      [N-1]:    CRC = sum(ADDR..DATA[-1]) & 0xFF
      [N]:      TAIL (0x55)

    ret_parse_process builds a 6-key dict: {head, addr, cmd, data, crc, tail}
    and uses UnicodeJoin to produce a space-separated hex string for logging.
    """

    def __init__(self):
        self.head = PACKET_HEAD
        self.tail = PACKET_TAIL

    def build_packet(self, addr, cmd, data_bytes=b''):
        payload = bytes([addr, cmd]) + data_bytes
        crc = sum(payload) & 0xFF
        return bytes([self.head]) + payload + bytes([crc, self.tail])

    def parse_packet(self, raw):
        """Parse raw bytes into a 6-key dict (matching ret_parse_process disassembly)."""
        if raw is None or len(raw) < 5:
            return None
        try:
            head = raw[0]; addr = raw[1]; cmd = raw[2]
            data = raw[3:-2]; crc = raw[-2]; tail = raw[-1]
            hex_pairs = ['{:02X}'.format(b) for b in raw]
            data_hex = ' '.join(hex_pairs)
            return {'head': head, 'addr': addr, 'cmd': cmd,
                    'data': data, 'crc': crc, 'tail': tail, 'data_hex': data_hex}
        except Exception:
            return None

    def get_cmd_num(self, data):
        if data is None or len(data) < 3:
            return None
        try:
            return data[2]
        except Exception:
            return None

    def parse_num_to_byte(self, num, length=1, byteorder='big'):
        try:
            return num.to_bytes(length, byteorder=byteorder)
        except Exception:
            return b'\x00' * length

    def parse_num_string_to_byte(self, num_string, length=1, byteorder='big'):
        try:
            return int(num_string).to_bytes(length, byteorder=byteorder)
        except Exception:
            return b'\x00' * length

    def get_key_from_value(self, d, value):
        for k, v in d.items():
            if v == value:
                return k
        return None

    def get_rfid(self, data):
        """
        Extract RFID from packet.
        From check_rfid_valid disassembly: validates len==17, extracts
        12 bytes at offset 4, formats as joined hex pairs.
        """
        if data is None:
            return None
        try:
            if len(data) < RFID_TOTAL_LEN:
                return None
            rfid_bytes = data[RFID_DATA_OFFSET:RFID_DATA_OFFSET + RFID_DATA_LEN]
            return ''.join('{:02X}'.format(b) for b in rfid_bytes)
        except Exception:
            return None

    def get_remain_len(self, data):
        """Extract remaining filament length (big-endian 4 bytes at offset 4)."""
        if data is None:
            return None
        try:
            return struct.unpack_from('>I', data, REMAIN_LEN_OFFSET)[0]
        except Exception:
            return None

    def get_measuring_wheel(self, data):
        """
        Extract measuring wheel counter.
        From disassembly: reads big-endian 4-byte value at offset 4,
        logs as 'data_hex: 0x%x, data:%s'.
        """
        if data is None:
            return None
        try:
            data_hex = struct.unpack_from('>I', data, MEASURING_OFFSET)[0]
            logging.info('[get_measuring_wheel] data_hex: 0x%x, data:%s', data_hex, data)
            return data_hex
        except Exception:
            return None

    def compute_crc(self, data_bytes):
        return sum(data_bytes) & 0xFF


class BoxCfg:
    """
    All configuration parameters for the box.

    From BoxCfg.__init__ disassembly (20KB):
    - ~20+ config keys, each loaded as {key, default, type} dict
    - Groups of 3-4 dict SetItems per config param group
    - PyNumber_Multiply for some default values (unit conversion)
    - UnicodeFormat for validation warning messages
    """

    def __init__(self, config):
        # Position config
        self.cut_pos_x           = config.getfloat('cut_pos_x', 0.)
        self.cut_pos_y           = config.getfloat('cut_pos_y', 0.)
        self.pre_cut_pos_x       = config.getfloat('pre_cut_pos_x', 0.)
        self.pre_cut_pos_y       = config.getfloat('pre_cut_pos_y', 0.)
        self.safe_pos_x          = config.getfloat('safe_pos_x', 0.)
        self.safe_pos_y          = config.getfloat('safe_pos_y', 0.)
        self.extrude_pos_x       = config.getfloat('extrude_pos_x', 0.)
        self.extrude_pos_y       = config.getfloat('extrude_pos_y', 0.)
        self.has_extrude_pos     = config.getint('has_extrude_pos', 0)
        # Cleaning config
        self.clean_velocity      = config.getfloat('clean_velocity', 10000.)
        self.clean_pos_min_x     = config.getfloat('clean_pos_min_x', 0.)
        self.clean_pos_min_y     = config.getfloat('clean_pos_min_y', 0.)
        self.clean_pos_max_x     = config.getfloat('clean_pos_max_x', 0.)
        self.clean_pos_max_y     = config.getfloat('clean_pos_max_y', 0.)
        self.clean_left_pos_x    = config.getfloat('clean_left_pos_x', 0.)
        self.clean_left_pos_y    = config.getfloat('clean_left_pos_y', 0.)
        self.clean_right_pos_x   = config.getfloat('clean_right_pos_x', 0.)
        self.clean_right_pos_y   = config.getfloat('clean_right_pos_y', 0.)
        self.clean_pos_middle_y  = config.getfloat('clean_pos_middle_y', 0.)
        self.clean_offset_pos    = config.getfloat('clean_offset_pos', 0.)
        # Physical
        self.trigger_pos         = config.getfloat('trigger_pos', 0.)
        self.nest_speed          = config.getfloat('nest_speed', 6000.)
        self.max_tube_length     = config.getfloat('max_tube_length', 800.)
        self.cut_velocity        = config.getfloat('cut_velocity', 3000.)
        self.cut_push_rod        = config.getfloat('cut_push_rod', 5.)
        # Lengths
        self.box_first_clean_length       = config.getfloat('box_first_clean_length', 100.)
        self.box_need_clean_length        = config.getfloat('box_need_clean_length', 50.)
        self.box_need_clean_length_max    = config.getfloat('box_need_clean_length_max', 200.)
        self.buffer_empty_len             = config.getfloat('buffer_empty_len', 100.)
        self.extrude_material_len_for_box = config.getfloat('extrude_material_len_for_box', 100.)
        self.extrude_material_velocity    = config.getfloat('extrude_material_velocity', 300.)
        self.box_extrude_retry_num        = config.getint('box_extrude_retry_num', 3)
        # Pins/bus
        self.switch_pin  = config.get('switch_pin', None)
        self.bus         = config.get('bus', 'serial485')
        # Timeouts
        self.cmd_timeout     = config.getfloat('cmd_timeout', TIMEOUT_LONG_TIME)
        self.extrude_timeout = config.getfloat('extrude_timeout', TIMEOUT_LONGER_TIME)
        # Material params
        self.min_extrude_temp      = config.getfloat('min_extrude_temp', 170.)
        self.flush_multiplier      = config.getfloat('flush_multiplier', 1.0)
        self.flush_velocity_factor = config.getfloat('flush_velocity_factor', 1.0)
        self.auto_refill           = config.getint('auto_refill', 0)

        logging.info('self.cut_pos_x: %f', self.cut_pos_x)
        logging.info('self.extrude_pos_x: %s', self.extrude_pos_x)
        logging.info('self.extrude_pos_y: %s', self.extrude_pos_y)
        logging.info('self.clean_velocity: %s', self.clean_velocity)
        logging.info('self.clean_left_pos_x: %s', self.clean_left_pos_x)
        logging.info('self.clean_right_pos_x: %s', self.clean_right_pos_x)


class BoxState:
    """
    Manages filament slot state.

    From update_tn_save_data disassembly (8.7KB):
    - 5-key nested dict per slot (rfid, material, color, remain_len, state)
    - 3 PyObject_SetItem per entry
    - _PyThreadState_UncheckedGet repeated (generator pattern - yields between slots)
    """

    def __init__(self, printer, config):
        self.printer = printer
        self.tn_save_data_path = 'creality/userdata/box/tn_data.json'
        self.tn_save_data = {}
        self.Tnn_map = {}
        self.e_err = None

    def state_init(self):
        self.Tnn_map = {}
        self.tn_save_data = {}

    def generate_Tnn_content(self, tnn):
        return {'tnn': tnn, 'color': None, 'material': None, 'rfid': None}

    def generate_Tnn_map(self, num):
        result = {}
        for i in range(num):
            key = 'T{}{}'.format(i // 4, i % 4)
            result[key] = self.generate_Tnn_content(key)
        return result

    def generate_Tn_data(self, num):
        return {'T{}'.format(i): {
            'rfid': None, 'material': None, 'color': None,
            'remain_len': None, 'state': None,
        } for i in range(num)}

    def get_Tn_data(self, tnn):
        if tnn is None:
            logging.warning('get Tn data error, has no part')
            return None
        return self.tn_save_data.get(tnn)

    def modify_Tn_data(self, tnn, key, value):
        if tnn is None:
            logging.warning('change Tn data error, has no part')
            return
        if tnn not in self.tn_save_data:
            self.tn_save_data[tnn] = {}
        self.tn_save_data[tnn][key] = value
        logging.info('Tn_data[%s][%s]: %s', tnn, key, value)

    def get_Tn_inner_data(self, part, key=None):
        if part is None:
            logging.warning('get Tn inner data error, has no part')
            return None
        data = self.tn_save_data.get(part)
        if key is not None and data is not None:
            return data.get(key)
        return data

    def modify_Tn_inner_data(self, part, key, value, subpart=None):
        if part is None:
            logging.warning('change Tn inner data error, has no part(%s)', part)
            return
        if part not in self.tn_save_data:
            self.tn_save_data[part] = {}
        if subpart is not None:
            if key not in self.tn_save_data[part]:
                self.tn_save_data[part][key] = {}
            self.tn_save_data[part][key][subpart] = value
            logging.info('Tn_inner_data[%s][%s][%s]: %s', part, key, subpart, value)
        else:
            self.tn_save_data[part][key] = value
            logging.info('Tn_inner_data[%s] = %s', part, value)

    def get_Tnn_content(self, tnn):
        return self.Tnn_map.get(tnn)

    def get_Tnn_map(self):
        return copy.deepcopy(self.Tnn_map)

    def sync_tn_data(self):
        try:
            if os.path.exists(self.tn_save_data_path):
                with open(self.tn_save_data_path, 'r') as f:
                    self.tn_save_data = json.load(f)
                logging.info('sync_tn_data loaded')
            else:
                logging.info('tn_save_data_path does not exist: %s', self.tn_save_data_path)
        except Exception as e:
            logging.warning('sync_tn_data error: %s', str(e))

    def get_tn_save_data(self, tnn):
        return self.tn_save_data.get(tnn)

    def modify_tn_save_data(self, tnn, key, value):
        if tnn is None:
            logging.warning('change tn save data error, has no part(%s)', tnn)
            return
        if tnn not in self.tn_save_data:
            self.tn_save_data[tnn] = {}
        self.tn_save_data[tnn][key] = value

    def update_tn_save_data(self):
        """
        Persist tn_data to JSON.
        Generator pattern (yields between slots) per _PyThreadState_UncheckedGet.
        5-key dict per slot; 3 SetItem calls for sub-entries.
        """
        try:
            dir_path = os.path.dirname(self.tn_save_data_path)
            if dir_path and not os.path.exists(dir_path):
                os.makedirs(dir_path, exist_ok=True)
            with open(self.tn_save_data_path, 'w') as f:
                json.dump(self.tn_save_data, f)
            logging.info('update_tn_save_data saved')
        except Exception as e:
            logging.warning('update_tn_save_data error: %s', str(e))

    def generate_tn_save_data(self):
        return copy.deepcopy(self.tn_save_data)

    def update_same_material_list(self, same_material_list):
        logging.info('same_material_list: %s, same_tnn_list: %s', same_material_list, [])

    def e_err_set(self, err):
        self.e_err = err

    def clear_e_err(self):
        self.e_err = None


class BoxSave:
    """Saves/restores printer state (fans, accel, error info, resume state)."""

    def __init__(self, printer):
        self.printer = printer
        self.gcode = None
        self.fan0_last_value = 0.
        self.fan2_last_value = 0.
        self.resume_tnn = None
        self.resume_flag = False
        self.err_tnn = None
        self.saved_max_accel = 5000.
        self.saved_max_accel_to_decel = 2500.

    def find_objs(self):
        self.gcode = self.printer.lookup_object('gcode')

    def save_fan(self):
        try:
            fan0 = self.printer.lookup_object('output_pin fan0', None)
            if fan0 is not None:
                self.fan0_last_value = fan0.last_value
                logging.info('fan0_last_value: %s', self.fan0_last_value)
            fan2 = self.printer.lookup_object('output_pin_fan2', None)
            if fan2 is not None:
                self.fan2_last_value = fan2.last_value
        except Exception as e:
            logging.warning("[box] do not define 'output_pin fan0': %s", str(e))

    def restore_fan(self):
        try:
            if self.gcode:
                self.gcode.run_script_from_command('SET_PIN PIN=fan0 VALUE=%.2f' % self.fan0_last_value)
                self.gcode.run_script_from_command('SET_PIN PIN=fan2 VALUE=%.2f' % self.fan2_last_value)
        except Exception as e:
            logging.warning('restore_fan error: %s', str(e))

    def save_printer_accel(self):
        try:
            toolhead = self.printer.lookup_object('toolhead')
            self.saved_max_accel = toolhead.get_max_accel()
            self.saved_max_accel_to_decel = toolhead.get_max_accel_to_decel()
            logging.info('max_accel = %s', self.saved_max_accel)
        except Exception as e:
            logging.warning('save_printer_accel error: %s', str(e))

    def restore_printer_accel(self):
        try:
            if self.gcode:
                self.gcode.run_script_from_command(
                    'SET_VELOCITY_LIMIT ACCEL=%.3f ACCEL_TO_DECEL=%.3f'
                    % (self.saved_max_accel, self.saved_max_accel_to_decel))
        except Exception as e:
            logging.warning('restore_printer_accel error: %s', str(e))

    def recode_err(self, err_key, tnn=None):
        self.err_tnn = tnn
        logging.warning('recode_err: %s, tnn: %s', err_key, tnn)

    def clear_err(self):
        self.err_tnn = None

    def save_err_tnn(self, tnn):
        self.err_tnn = tnn

    def save_resume_tnn(self, tnn):
        self.resume_tnn = tnn
        self.resume_flag = True
        logging.info('set resume_flag')

    def clear_resume_tnn(self):
        self.resume_tnn = None
        self.resume_flag = False
        logging.info('clear the data of power loss')

    def get_err(self):
        return self.err_tnn


class CutSensor:
    """Manages the filament cutting hall/switch sensor."""

    def __init__(self, printer, config):
        self.printer = printer
        self.cut_present = False
        switch_pin = config.get('switch_pin', None)
        if switch_pin is None:
            logging.warning("[box] do not define 'switch_pin' for cutting")
            return
        buttons = printer.load_object(config, 'buttons')
        buttons.register_buttons([switch_pin], self._button_handler)

    def _button_handler(self, eventtime, state):
        self.cut_present = bool(state)
        logging.info('[box] cut sensor %s', 'detected' if state else 'not detected')

    def state(self):
        return self.cut_present


class BoxAction:
    """
    Core action handler for serial communication with the box.

    Key method sizes from disassembly:
      process_msg           96KB  - message dispatcher (~50 branches, consts 17/24/11/12)
      update_state_process  62KB  - state update, Lshift bit extract, generator
      send_data             40KB  - 5-retry, 6-key packet dict, UnicodeJoin
      material_auto_refill  32KB  - 4-key dicts, list iteration, PyObjectSize
      Tn_Extrude            29KB  - multi-stage, size checks, Multiply for volume
      box_extrude_material_part 24KB - 3-4 stage extrusion, RichCompare
      box_extrude_material  19KB  - orchestrator
      filament_err_tighten  15KB  - And bitmask, subtract+compare cycles
    """

    def __init__(self, printer, config, boxcfg, boxstate, boxsave, cut_sensor, parse_data):
        self.printer = printer
        self.boxcfg = boxcfg
        self.box_state = boxstate
        self.box_save = boxsave
        self.cut = cut_sensor
        self.parse_data = parse_data
        self.reactor = printer.get_reactor()
        self._serial = None
        self.gcode = None
        self.toolhead = None

        # Addressing
        self.addr_manager_table_mb = None
        self.auto_get_rfid_addr = None

        # Tnn state
        self.current_tnn = None
        self.last_tnn = None
        self.next_tnn = None
        self.last_cmd = None
        self.current_cmd = None
        self.Tnn_map = {}

        # Error state
        self.error_list = []
        self.error_times = 0
        self.error_index = None
        self.error_tnn = None

        # Heart process
        self.heart_process_enable = False

        # Flushing
        self.flushing_sign = False

        # Extrude state machine
        self.extrude_process_stage7_flag = False
        self.extrude_process_stage7_ret = None
        self.extrude_process_ret_state = None

        # Material
        self.material_auto_refill_flag = False
        self.is_use_ending_material = False

        # Retry / timeout
        self.retry_index = 0
        self.timeout_times = 0
        self.cmd_timeout = boxcfg.cmd_timeout
        self.extrude_timeout = boxcfg.extrude_timeout

        # Auto-retry flags
        self.auto_retry_connection = False
        self.auto_retry_filament_sensor = False
        self.auto_retry_extruder_gear = False

        # Hardware counters
        self.cut_succeed_num = 0
        self.cut_cycle_index = 0
        self.cut_release_succeed = False
        self.cut_release_failed = False

        # Flush data
        self.flush_data_matrix = []
        self.flush_array = []
        self.same_material_list = []

        # Measuring wheel
        self.last_measuring_wheel = None
        self.diff_length = 0.

        # Per-slot extrude params
        self.Tn_extrude_velocity = {}
        self.Tn_extrude_percent = {}
        self.Tn_extrude_temp = {}

        # Speed factors
        self.speed_factor = 1.0
        self.flush_velocity_factor = boxcfg.flush_velocity_factor

        # Data parts
        self.data_upper_parts = []
        self.inner_data_parts = []

        # Power loss
        self.power_loss_clean_flag = False

        # RFID
        self.tnn_rfid = None

        # Material db path
        self.material_database_path = 'creality/userdata/box/material_database.json'

        self.lock = threading.Lock()

    def find_objs(self):
        self.gcode = self.printer.lookup_object('gcode')
        self.toolhead = self.printer.lookup_object('toolhead')
        self.pause_resume = self.printer.lookup_object('pause_resume', None)
        bus = getattr(self.boxcfg, 'bus', 'serial485')
        for name in ('serial_485 ' + bus, 'serial_485'):
            try:
                self._serial = self.printer.lookup_object(name)
                break
            except Exception:
                pass
        if self._serial is None:
            logging.warning(
                'the bus of box is not configured, it is the name of serial_485, '
                'such as [serial_485 serial485] and bus: serial485')

    def _handle_ready(self):
        logging.info('box:ready')
        self.find_objs()
        self.box_state.sync_tn_data()
        self.printer.register_event_handler('klippy:shutdown', self._handle_shutdown)

    def _handle_shutdown(self):
        logging.info('klippy:shutdown')
        self.heart_process_enable = False

    def enable_filament_sensor(self):
        try:
            self.gcode.run_script_from_command(
                'SET_FILAMENT_SENSOR SENSOR=filament_sensor ENABLE=1')
            logging.info('filament sensor true')
        except Exception:
            pass

    def disable_filament_sensor(self):
        try:
            self.gcode.run_script_from_command(
                'SET_FILAMENT_SENSOR SENSOR=filament_sensor ENABLE=0')
            logging.info('filament sensor false')
        except Exception:
            pass

    def enable_heart_process(self):
        self.heart_process_enable = True
        logging.info('enable_heart_process')

    def disable_heart_process(self):
        self.heart_process_enable = False
        logging.info('disable_heart_process')

    def set_flushing_sign(self):
        self.flushing_sign = True
        try:
            path = 'creality/userdata/config/flushing_sign'
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w') as f:
                f.write('1')
        except Exception:
            pass

    def reset_flushing_sign(self):
        self.flushing_sign = False
        try:
            path = 'creality/userdata/config/flushing_sign'
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass

    def has_flushing_sign(self):
        return self.flushing_sign

    def check_same_box(self, addr1, addr2):
        if addr1 is None or addr2 is None:
            return False
        return addr1 == addr2

    # ---- Low-level serial ----

    def motor_send_data(self, addr, data_bytes, timeout=None):
        if self._serial is None:
            return None
        try:
            return self._serial.send_data(addr, data_bytes)
        except Exception as e:
            logging.warning('motor_send_data error: %s', str(e))
            return None

    def send_data(self, addr, cmd, data_bytes=b'', timeout=None):
        """
        Send packet with 5-retry loop.

        From disassembly (40KB):
        - Builds 6-key dict: {head,addr,cmd,data,crc,tail}
        - UnicodeJoin: ' '.join(hex_pairs) for logging
        - const 5: retry loop
        - RichCompare: timeout comparison
        - UnicodeFormat: 'data_send:%s recv_result:%s'
        - Warning: '%d.timeout, TIMEOUT=%.2f, send data: 0x%x'
        - Warning: '%d.get return data(0x%x) error, send data: 0x%x'
        """
        if timeout is None:
            timeout = self.cmd_timeout
        packet = self.parse_data.build_packet(addr, cmd, data_bytes)
        data_hex = ' '.join('{:02X}'.format(b) for b in packet)

        for attempt in range(MAX_SEND_RETRIES):
            result = self.motor_send_data(addr, packet, timeout)
            logging.info('data_send:%s recv_result:%s', data_hex, result)
            if result is None:
                self.timeout_times += 1
                logging.warning('%d.timeout, TIMEOUT=%.2f, send data: 0x%x',
                               self.timeout_times, timeout, cmd)
                continue
            parsed = self.parse_data.parse_packet(result) if isinstance(
                result, (bytes, bytearray)) else result
            if parsed is None:
                continue
            recv_cmd = parsed.get('cmd') if isinstance(parsed, dict) else (
                result[2] if len(result) > 2 else None)
            if recv_cmd != cmd:
                logging.warning('%d.get return data(0x%x) error, send data: 0x%x',
                               self.timeout_times, recv_cmd or 0, cmd)
                continue
            return parsed
        return None

    def ret_parse_process(self, data, expected_cmd):
        """
        Parse and validate a response packet.

        From disassembly (3.3KB):
        - Builds 6-key dict (same as send_data)
        - UnicodeJoin for hex
        - UnicodeFormat for log
        - RichCompare for cmd check
        - PyType_IsSubtype x2 for type validation
        """
        if data is None:
            return None
        parsed = self.parse_data.parse_packet(data) if isinstance(
            data, (bytes, bytearray)) else data
        if parsed is None:
            return None
        cmd_num = parsed.get('cmd') if isinstance(parsed, dict) else None
        if cmd_num != expected_cmd:
            logging.warning('%d.get return data(0x%x) error, send data: 0x%x',
                           self.timeout_times, cmd_num or 0, expected_cmd)
            return None
        return parsed

    def process_msg(self, data):
        """
        Main message dispatcher (96KB - largest function).

        From disassembly:
        - Consts 17 and 24 for packet size branches
        - Const 11 for sub-field offset
        - ~50 PyType_IsSubtype+PyTuple_New blocks = ~50 message branches
        - UnicodeJoin for hex-string formatting throughout
        - PyList_New for data list construction
        - PyDict_New + 1 key SetItem per sub-entry
        - PyObject_GetIter + loop for multi-entry responses
        - PyNumber_Remainder for formatting
        - Multiple RichCompare for state comparisons
        - Const 5 for address range or retry limit
        - Two PyUnicodeJoin calls (data_hex + response_hex)
        - UnicodeFormat: 'update_state_process, data: %s'
        - Warning: '[unknown scene] ret: %s, ret_state: %s'
        """
        if data is None:
            return None
        try:
            raw = data
            if len(raw) < 5:
                return None
            head = raw[0]; addr = raw[1]; cmd = raw[2]
            payload = raw[3:-2]; crc = raw[-2]; tail = raw[-1]

            hex_pairs = ['{:02X}'.format(b) for b in raw]
            data_hex = ' '.join(hex_pairs)
            logging.info('update_state_process, data: %s', data_hex)

            if head != PACKET_HEAD or tail != PACKET_TAIL:
                logging.warning('[unknown scene] ret: %s, ret_state: %s', data_hex, None)
                return None

            parsed = {'head': head, 'addr': addr, 'cmd': cmd,
                      'data': payload, 'crc': crc, 'tail': tail}

            if cmd == CMD_TEST:
                logging.info('%d. addr[%d] test finish', self.timeout_times, addr)
            elif cmd == CMD_CREATE_CONNECT:
                pass
            elif cmd == CMD_EXTRUDE:
                if len(payload) >= 1:
                    self._handle_extrude_response(addr, payload[0], payload)
            elif cmd == CMD_RETRUDE:
                if len(payload) >= 1:
                    self._handle_retrude_response(addr, payload[0], payload)
            elif cmd == CMD_GET_BOX_STATE:
                if len(payload) >= 1:
                    self._decode_box_state(addr, payload)
            elif cmd == CMD_GET_RFID:
                # Packet must be >= 17 bytes (RFID_TOTAL_LEN)
                if len(raw) >= RFID_TOTAL_LEN:
                    rfid = self.parse_data.get_rfid(raw)
                    logging.info('tnn_rfid: %s', rfid)
                    self.tnn_rfid = rfid
            elif cmd == CMD_GET_REMAIN_LEN:
                remain = self.parse_data.get_remain_len(raw)
                logging.info('remain_len: %s', remain)
            elif cmd == CMD_GET_VERSION:
                # Version packet >= 24 bytes (from const 24 in disassembly)
                if len(raw) >= 24:
                    ver = raw[3:11].decode('utf-8', errors='ignore').rstrip('\x00')
                    sn  = raw[11:23].hex()
                    logging.info('version: %s, sn: %s', ver, sn)
            elif cmd == CMD_GET_BUFFER:
                if len(payload) >= 1:
                    logging.info('buffer_state: 0x%x', payload[0])
            elif cmd == CMD_GET_FILAMENT:
                if len(payload) >= 1:
                    logging.info('[box] filament sensor state: %x', payload[0])
                    self._decode_filament_state(addr, payload[0])
            elif cmd == CMD_MEAS_WHEEL:
                measuring = self.parse_data.get_measuring_wheel(raw)
                if measuring is not None:
                    logging.info('measuring_wheel = %d', measuring)
                    if self.last_measuring_wheel is not None:
                        self.diff_length = measuring - self.last_measuring_wheel
                    self.last_measuring_wheel = measuring
            else:
                logging.warning('[unknown scene] ret: %s, ret_state: %s', data_hex, cmd)

            return parsed
        except Exception as e:
            logging.warning('process_msg error: %s', str(e))
            return None

    def _decode_box_state(self, addr, payload):
        """Decode box state byte. Uses bit ops (from update_state_process: Lshift)."""
        state = payload[0]
        # From update_state_process: uses << (Lshift) to extract bit fields
        error_code   = (state >> 4) & 0xF
        action_state = (state >> 2) & 0x3
        connection   = state & 0x3
        logging.info('[box] state: 0x%x err=%d action=%d conn=%d',
                    state, error_code, action_state, connection)

    def _decode_filament_state(self, addr, sensor_byte):
        """Decode filament sensor byte (bit per slot)."""
        logging.info('get_connect_state: get_filament_sensor_state material_status:%s',
                    sensor_byte)

    def _handle_extrude_response(self, addr, state_byte, payload):
        pass

    def _handle_retrude_response(self, addr, state_byte, payload):
        pass

    def update_state_process(self, data):
        """
        Process state update (62KB, 2nd largest).

        From disassembly:
        - PyNumber_Lshift for bit field extraction
        - PyNumber_Add x3 (state accumulation, e.g. addr<<8|cmd)
        - _PyThreadState_UncheckedGet (generator/coroutine pattern)
        - Large type dispatch (many PyType_IsSubtype+PyTuple_New)
        - Multiple RichCompare (state value comparisons)
        - PyDict_New/SetItem for building state dicts (4 and 2 key variants)
        """
        logging.info('update_state_process, data: %s', data)
        if data is None:
            return
        try:
            if isinstance(data, dict):
                payload = data.get('data', b'')
                addr = data.get('addr', 0)
                cmd  = data.get('cmd', 0)
            else:
                return
            if not payload or len(payload) < 1:
                return
            state = payload[0]
            # Bit field extraction via shifts (Lshift from disassembly)
            error_code   = (state >> 4) & 0xF
            action_state = (state >> 2) & 0x3
            connection   = state & 0x3
            logging.info('state: %s[0x%x]', state, state)
            if error_code:
                logging.warning('[warning] cmd: %s, state: %s, report_err: %s',
                               cmd, state, error_code)
        except Exception as e:
            logging.warning('update_state_process error: %s', str(e))

    def timeout_process(self, timeout=None):
        if timeout is None:
            timeout = self.cmd_timeout
        self.timeout_times += 1
        logging.warning('%d.timeout, TIMEOUT=%.2f, send data: 0x%x',
                       self.timeout_times, timeout, 0)

    def check_connect(self, addr):
        if addr is None:
            logging.warning('[error] addr: %s', addr)
            return False
        result = self.communication_get_box_state(addr)
        if result is None:
            logging.warning('addr[%s] is not connected', addr)
            return False
        return True

    def check_rfid_valid(self, rfid):
        """
        Validate RFID string.

        From disassembly (6.2KB):
        - Consts 17 and 12 at start (length validation)
        - PyObject_Size for len() checks
        - PyList_New + PyDict_New for result building
        - UnicodeFormat for warnings
        - PyNumber_Remainder for format
        - PyType_IsSubtype x3 (string/bytes type checks)
        - RichCompare for equality check (all-zeros check)
        """
        if rfid is None:
            return False
        if len(rfid) != RFID_DATA_LEN * 2:   # 24 hex chars
            logging.warning('rfid is error, get rfid: %s', rfid)
            return False
        if all(c == '0' for c in rfid):
            logging.warning('rfid is error, get rfid: %s', rfid)
            return False
        return True

    def get_gcode_used_tnn(self):
        try:
            sd = self.printer.lookup_object('virtual_sdcard', None)
            if sd is None:
                return None
            metadata = getattr(sd, 'file_metadata', None)
            if metadata:
                return metadata.get('gcode_used_tnn')
        except Exception:
            pass
        return None

    def check_printing_used_material(self, tnn):
        used = self.get_gcode_used_tnn()
        if used is None:
            return True
        return tnn in used

    def check_material_refill(self, tnn):
        logging.info('check_material_refill tnn: %s', tnn)

    def material_auto_refill(self, tnn):
        """
        Automated material refill (32KB).

        From disassembly:
        - PyDict_New + 4 SetItem (4-key state dicts)
        - PyDict_New + 2 SetItem (2-key status dicts)
        - UnicodeFormat: 'material_quantity: %d'
        - PyObject_Size: list length validation
        - PyObject_GetIter + loops: iterating slot list
        - RichCompare x3: state comparisons
        - PyObject_SetItem: state updates
        - Const 5: max slots or retries
        """
        self.material_auto_refill_flag = True
        logging.info('material_auto_refill tnn: %s', tnn)
        logging.info('material_quantity: %d', 0)

    def is_material_available(self, tnn):
        return tnn is not None

    def update_Tnn_map(self, tnn, content):
        if tnn is None:
            logging.warning('[error] tnn is None, last_tnn: %s, tnn: %s',
                           self.last_tnn, tnn)
            return
        self.box_state.Tnn_map[tnn] = content
        self.Tnn_map[tnn] = content

    def update_same_material_list(self, same_material_list):
        self.same_material_list = same_material_list
        self.box_state.update_same_material_list(same_material_list)

    def _load_material_db(self):
        try:
            if os.path.exists(self.material_database_path):
                with open(self.material_database_path, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def get_flush_temp(self, last_tnn, tnn):
        db = self._load_material_db()
        logging.info('flush_temp: %d', 0)
        return None

    def get_flush_max_temp(self, last_tnn, tnn):
        logging.info('flush_max_temp: %d', 0)
        return None

    def get_material_target_temp(self, tnn):
        """
        Get nozzle target temp (11KB).

        From disassembly:
        - Const 6 (field offset in material record)
        - _PyThreadState_UncheckedGet (generator)
        - PyList_New + PyType_IsSubtype (list type dispatch)
        - PyObject_Size (list len check)
        - PyDict_New x4 (building result dicts)
        - PyNumber_Long (int conversion of temp value)
        - Logs: 'material database get nozzle temp: %s'
        - Logs: 'get material target temp fail'
        """
        db = self._load_material_db()
        if tnn is None:
            logging.warning('get material target temp fail')
            return None
        content = self.box_state.get_Tnn_content(tnn)
        if content is None:
            logging.warning('get material target temp fail')
            return None
        material = content.get('material')
        if material is None:
            logging.warning('get material target temp fail')
            return None
        temp = db.get(material, {}).get('nozzle_temp')
        logging.info('material database get nozzle temp: %s', temp)
        return int(temp) if temp is not None else None

    def get_material_target_max_temp(self, tnn):
        """
        Get max nozzle temp (11KB, same structure as get_material_target_temp).

        Logs: 'material database get nozzle max temp: %s'
        Logs: 'get material target max temp fail'
        """
        db = self._load_material_db()
        if tnn is None:
            logging.warning('get material target max temp fail')
            return None
        content = self.box_state.get_Tnn_content(tnn)
        if content is None:
            logging.warning('get material target max temp fail')
            return None
        material = content.get('material')
        if material is None:
            logging.warning('get material target max temp fail')
            return None
        temp = db.get(material, {}).get('nozzle_max_temp')
        logging.info('material database get nozzle max temp: %s', temp)
        return int(temp) if temp is not None else None

    def get_material_max_extrusion_speed(self, tnn):
        """
        Get max extrusion speed (11.3KB).

        From disassembly:
        - Same structure as temp functions + const 6
        - PyFloat_FromDouble: float conversion
        - PyErr_Occurred: validates result
        - Logs: 'get material extrusion speed: %d'
        - Logs: 'get material extrusion speed fail'
        - Logs: 'get_material_max_extrusion_speed'
        - Logs: 'max_volumetric_speed: %s'
        """
        db = self._load_material_db()
        logging.info('get_material_max_extrusion_speed')
        if tnn is None:
            logging.warning('get material extrusion speed fail')
            return None
        content = self.box_state.get_Tnn_content(tnn)
        if content is None:
            logging.warning('get material extrusion speed fail')
            return None
        material = content.get('material')
        if material is None:
            logging.warning('get material extrusion speed fail')
            return None
        speed = db.get(material, {}).get('max_volumetric_speed')
        logging.info('max_volumetric_speed: %s', speed)
        if speed is not None:
            try:
                s = float(speed)
                logging.info('get material extrusion speed: %d', int(s))
                return s
            except Exception:
                pass
        logging.warning('get material extrusion speed fail')
        return None

    def get_flush_velocity(self, last_tnn, tnn):
        speed = self.get_material_max_extrusion_speed(tnn)
        if speed is None:
            return None
        return speed * self.flush_velocity_factor

    def get_flush_len(self, last_tnn, tnn):
        if last_tnn is None or tnn is None:
            logging.warning(
                '[warning] do not get flush_len check the color_value of '
                'last_tnn(%s) and current(%s)', last_tnn, tnn)
            return None
        return None

    def cal_flush_list(self, tnn_list):
        """
        Calculate flush list for a Tnn sequence (5.2KB).

        From disassembly:
        - Const 5 used twice (max flush entries)
        - PyNumber_InPlaceSubtract (decrement counter)
        - PyNumber_Subtract + TrueDivide (volume normalization)
        - PyNumber_InPlaceAdd + SetItem (accumulate flush array)
        - Multiple RichCompare (bounds check)
        - PyObject_GetIter + loop: iterates tnn list
        - PyErr_Occurred + PyErr_Clear: iterator exhaustion
        """
        result = []
        if not tnn_list or len(tnn_list) < 2:
            return result
        for i in range(min(len(tnn_list) - 1, MAX_SEND_RETRIES)):  # max 5
            last_tnn = tnn_list[i]
            tnn = tnn_list[i + 1]
            flush_len = self.get_flush_len(last_tnn, tnn)
            if flush_len is not None and flush_len > 0:
                result.append((last_tnn, tnn, flush_len))
        logging.info('flush_array: %s', result)
        return result

    def quickly_wait_heating(self, temp, timeout=60.):
        """
        Wait for nozzle to reach temp (3.2KB).

        From disassembly:
        - Const 10 used twice (check interval seconds)
        - UnicodeFormat: format status string
        - PyNumber_Remainder: modulo for timing
        - RichCompare x2: temp comparisons
        - reactor.pause for sleeping
        """
        logging.info('quickly_wait_heating temp: %s', temp)
        heater = None
        try:
            heater = self.printer.lookup_object('extruder').get_heater()
        except Exception:
            return
        eventtime = self.reactor.monotonic()
        deadline = eventtime + timeout
        check_interval = 10.0   # from const=10 in disassembly
        while True:
            eventtime = self.reactor.pause(eventtime + check_interval)
            if heater and heater.smoothed_temp >= temp:
                break
            if eventtime > deadline:
                logging.warning('extrude timeout, test: %s', temp)
                break

    def convert_tcv(self, last_tnn, tnn, cv):
        if cv is None or len(cv) != 6:
            logging.warning('warning, the length of "TCV" is not 6')
            return cv
        return cv

    def convert_scv(self, last_tnn, tnn, cv):
        if cv is None or len(cv) != 6:
            logging.warning('warning, the length of "SCV" is not 6')
            return cv
        return cv

    def set_temp(self, temp):
        self.gcode.run_script_from_command('M104 S%.2f' % temp)
        logging.info('set target max temp')

    def set_cool_temp(self):
        self.gcode.run_script_from_command('M104 S140')
        logging.info('restore target temp')

    def get_filament_sensor_detect(self):
        try:
            sensor = self.printer.lookup_object(
                'filament_switch_sensor filament_sensor', None)
            if sensor is None:
                return None
            return sensor.runout_helper.filament_present
        except Exception:
            return None

    def get_five_way_sensor_detect(self):
        try:
            sensor = self.printer.lookup_object(
                'filament_switch_sensor five_way_filament', None)
            if sensor is None:
                return None
            return sensor.runout_helper.filament_present
        except Exception:
            return None

    def blow(self):
        try:
            self.gcode.run_script_from_command('SET_PIN PIN=fan0 VALUE=255')
            logging.info('cmd_blow')
        except Exception:
            pass

    def move_to_safe_pos(self):
        self.gcode.run_script_from_command(
            'G0 X%.2f Y%.2f F12000' % (self.boxcfg.safe_pos_x, self.boxcfg.safe_pos_y))

    def go_to_extrude_pos(self):
        if not self.boxcfg.has_extrude_pos:
            logging.warning('machine has extrude pos')
            return
        logging.info('self.extrude_pos_x: %s', self.boxcfg.extrude_pos_x)
        logging.info('self.extrude_pos_y: %s', self.boxcfg.extrude_pos_y)
        self.gcode.run_script_from_command(
            'G0 X%.2f Y%.2f F12000' % (self.boxcfg.extrude_pos_x, self.boxcfg.extrude_pos_y))

    def move_to_cut(self):
        logging.info('self.boxcfg.cut_pos_x: %f', self.boxcfg.cut_pos_x)
        self.gcode.run_script_from_command(
            'G0 X%.2f Y%.2f F10000' % (self.boxcfg.cut_pos_x, self.boxcfg.cut_pos_y))

    def nozzle_clean(self):
        """
        Nozzle cleaning wipe sequence (9.4KB).

        From disassembly:
        - 8 PyUnicode_Format + 8 PyTuple_New calls = 8 formatted GCode moves
        - PyNumber_Add (position offset addition)
        - PyNumber_Subtract (position subtraction for return)
        - Logs all position values before executing
        - Sequence: wipe left↔right x3, circle cut at cut_pos
        """
        logging.info('self.clean_velocity: %s', self.boxcfg.clean_velocity)
        logging.info('self.clean_left_pos_x: %s', self.boxcfg.clean_left_pos_x)
        logging.info('self.clean_left_pos_y: %s', self.boxcfg.clean_left_pos_y)
        logging.info('self.clean_right_pos_x: %s', self.boxcfg.clean_right_pos_x)
        logging.info('self.clean_right_pos_y: %s', self.boxcfg.clean_right_pos_y)
        logging.info('self.clean_pos_min_x: %s', self.boxcfg.clean_pos_min_x)
        logging.info('self.clean_pos_min_y: %s', self.boxcfg.clean_pos_min_y)
        logging.info('self.clean_pos_max_x: %s', self.boxcfg.clean_pos_max_x)
        logging.info('self.clean_pos_max_y: %s', self.boxcfg.clean_pos_max_y)

        v = self.boxcfg.clean_velocity
        lx = self.boxcfg.clean_left_pos_x
        ly = self.boxcfg.clean_left_pos_y
        rx = self.boxcfg.clean_right_pos_x
        ry = self.boxcfg.clean_right_pos_y
        off = self.boxcfg.clean_offset_pos

        # 8 GCode moves (from 8 UnicodeFormat calls in disassembly)
        script = (
            'G0 X%.2f Y%.2f F%.2f\n' % (lx, ly, v) +
            'G0 X%.2f Y%.2f F%.2f\n' % (rx, ry, v) +
            'G0 X%.2f Y%.2f F%.2f\n' % (lx, ly, v) +
            'G0 X%.2f Y%.2f F%.2f\n' % (rx, ry, v) +
            'G0 X%.2f Y%.2f F%.2f\n' % (lx, ly, v) +
            'G0 X%.2f Y%.2f F%.2f\n' % (lx + off, ly, v) +
            'G2 I4 J0 P1 F10000\n' +
            'G3 I-4 J0 P1 F10000\n' +
            'M400'
        )
        self.gcode.run_script_from_command(script)

    def z_move(self, z):
        self.gcode.run_script_from_command(
            'G91\n G0 F600\nG0 Z%.2f F600\n\nG90' % z)

    def cut_hall_find_zero(self):
        logging.info('[box] cut to return OK')

    def cut_hall_test(self):
        logging.info('[box] cut sensor state test')
        return self.cut.state()

    def cut_hall_zero(self):
        logging.info('[box] cut sensor zero')

    def cut_material(self):
        """Execute filament cut (CW + CCW arc)."""
        logging.info('self.boxcfg.cut_pos_x: %f', self.boxcfg.cut_pos_x)
        if self.cut.state():
            logging.info('[box] cut sensor detected')
        else:
            logging.info('[box] cut sensor not detected')
        self.gcode.run_script_from_command(
            'G0 X%.2f Y%.2f F%.2f' % (
                self.boxcfg.cut_pos_x, self.boxcfg.cut_pos_y,
                self.boxcfg.cut_velocity))
        self.gcode.run_script_from_command('G2 I4 J0 P1 F10000')
        if not self.cut.state():
            logging.info('[box] cut to return failed')
            self.cut_release_failed = True
            return False
        self.gcode.run_script_from_command('G3 I-4 J0 P1 F10000')
        logging.info('[box] cut to return OK')
        self.cut_succeed_num += 1
        self.cut_release_succeed = True
        return True

    def make_material_loose(self, tnn):
        self.gcode.run_script_from_command('G0 E-2 F600')

    def material_volume_to_length(self, volume, tnn=None):
        """Convert volumetric mm³ to linear mm. From disassembly: Multiply op."""
        try:
            diameter = 1.75
            db = self._load_material_db()
            if tnn:
                content = self.box_state.get_Tnn_content(tnn)
                if content:
                    material = content.get('material')
                    if material:
                        diameter = db.get(material, {}).get('filament_diameter', 1.75)
            r = diameter / 2.0
            return volume / (math.pi * r * r)
        except Exception:
            return volume

    def Tn_Extrude(self, tnn, length, velocity, temp=None):
        """
        Extrude a Tnn slot (29KB, complex state machine).

        From disassembly:
        - Const 5 used for retry/max count
        - PyObject_Size + RichCompare: validates extrude_velocity/percent list sizes
        - PyNumber_Multiply: volume to length conversion
        - PyList_New: builds extrude sequence list
        - PyDict_New + 1 key SetItem per step
        - PyLong_FromSsize_t: index to int
        - PyNumber_Subtract + InPlaceAdd: accumulated extrusion tracking
        - UnicodeFormat: 'extrude = %s' and 'extrude_process_stage7 tnn: %s'
        - Warning: 'Tn_extrude_percent[%s] and Tn_extrude_velocity[%s] mismatch.'
        - Warning: 'TNN[%s] not in Tnn gcode'
        """
        logging.info('extrude = %s', length)
        logging.info('extrude_process_stage7 tnn: %s', tnn)

        if length is None or length <= 0:
            return

        # Validate velocity/percent arrays
        vel = velocity
        pct = 100.
        if tnn and tnn in self.Tn_extrude_velocity:
            vel = self.Tn_extrude_velocity[tnn]
        if tnn and tnn in self.Tn_extrude_percent:
            pct = self.Tn_extrude_percent[tnn]

        if (len(self.Tn_extrude_velocity) > 0 and len(self.Tn_extrude_percent) > 0 and
                len(self.Tn_extrude_velocity) != len(self.Tn_extrude_percent)):
            logging.warning('Tn_extrude_percent[%s] and Tn_extrude_velocity[%s] mismatch.',
                           tnn, tnn)

        used = self.get_gcode_used_tnn()
        if used is not None and tnn not in used:
            logging.warning('TNN[%s] not in Tnn gcode', tnn)

        if temp is not None:
            self.set_temp(temp)
            self.quickly_wait_heating(temp)

        actual_length = length * (pct / 100.0)
        self.gcode.run_script_from_command('G0 E%.2f F%.2f' % (actual_length, vel))

    def extruder_extrude(self, length, velocity):
        self.gcode.run_script_from_command('G0 E%.2f F%.2f' % (length, velocity))

    def extrude_process_stage7(self, tnn, addr):
        logging.info('extrude_process_stage7 tnn: %s', tnn)
        logging.info('box:extrude_process_stage7')
        self.extrude_process_stage7_flag = True
        result = self.communication_extrude_process(
            addr,
            self.boxcfg.extrude_material_len_for_box,
            self.boxcfg.extrude_material_velocity,
            100.)
        self.extrude_process_stage7_ret = result
        if result is None:
            self.extrude_process_stage7_flag = False

    def extrude_process_auto_retry_process(self, tnn):
        """
        Auto-retry logic (11.3KB).

        From disassembly:
        - PyDict_New + 4 SetItem (4-key retry state dict)
        - PyObject_GetItem x2 + PyType_IsSubtype (type dispatch)
        - PyObject_SetItem x3 (state updates)
        - PyDict_New + 1 key x4 (per-retry command dicts)
        - PyObject_GetItem x2 (state reads) x2 more sets
        """
        logging.info('extrude_process_auto_retry_process')
        self.retry_index += 1
        if self.retry_index > self.boxcfg.box_extrude_retry_num:
            logging.warning('extrude more than %d', self.boxcfg.box_extrude_retry_num)
            self.retry_index = 0
            return False
        return True

    def material_flush(self, last_tnn, tnn, flush_len):
        logging.info('flush; last_tnn: %s, current_tnn: %s', last_tnn, tnn)
        logging.info('flush_len: %s', flush_len)
        if flush_len and flush_len > 0:
            self.check_flush_temp_and_extrude(last_tnn, tnn, flush_len)

    def box_extrude_material(self, tnn, addr, length, velocity):
        """
        Extrude from box (19KB).

        From disassembly:
        - PyDict_New + 2 SetItem (2-key command dict)
        - PyObject_GetItem (box state read)
        - Multiple PyType_IsSubtype dispatch blocks
        - PyObject_GetIter + loop (multi-address handling)
        - PyNumber_Multiply (length conversion)
        - PyTuple_New + Remainder (logging)
        """
        logging.info('box_extrude_material tnn: %s, addr: %s', tnn, addr)
        result = self.communication_extrude_process(addr, length, velocity, 100.)
        if result is None:
            logging.warning(
                '!! {"code":"key831", "msg":"serial_485 communication timeout", '
                '"values": [%d]}', addr)
            return False
        return True

    def box_extrude_material_part(self, tnn, addr, length, velocity):
        """
        Partial extrusion (24KB, 3rd largest).

        From disassembly:
        - PyDict_New + 4 SetItem + 2 SetItem (two command dicts)
        - PyTuple_New + PyDict_New + 1 key (per-step cmd)
        - PyObject_GetItem x2 + RichCompare (state check)
        - UnicodeFormat: progress logging
        - Pattern repeats 3-4 times (stages)
        - PyObject_SetItem (state updates)
        """
        logging.info('box_extrude_material_part tnn: %s, addr: %s', tnn, addr)
        result = self.communication_extrude_process(addr, length, velocity, 100.)
        if result is None:
            return False
        state = self.communication_get_box_state(addr)
        return state is not None

    def box_extrude_material_stage8(self, tnn, addr):
        """
        Stage 8 verification (10KB).

        From disassembly:
        - PyTuple_New + UnicodeFormat
        - PyTuple_New + PyDict_New + 3 keys
        - Multiple type dispatch blocks
        - Returns 'stage8 return error' string on fail
        """
        logging.info('stage8 return error')
        state = self.communication_get_box_state(addr)
        if state is None:
            return 'stage8 return error'
        return state

    def box_retrude_material(self, tnn, addr, length, velocity):
        logging.info('box_retrude_material tnn: %s, addr: %s', tnn, addr)
        result = self.communication_retrude_process(addr, length, velocity)
        if result is None:
            logging.warning(
                '!! {"code":"key849", "msg":"retrude error, failed to exit connections", '
                '"values": [%d, "%s"]}', addr, tnn)
            return False
        return True

    def box_retrude_material_filament_err_part(self, tnn, addr):
        logging.info('box_retrude_material_filament_err_part')
        self.gcode.run_script_from_command('G0 E-15 F120')

    def retrude_process_clear_flag(self):
        logging.info('retrude_process_clear_flag')

    def use_ending_material_flag_clear(self):
        self.is_use_ending_material = False
        logging.info('use_ending_material_flag_clear')

    def is_use_ending_material_flush(self, tnn):
        """
        Check ending-material flush flag (7.2KB).

        From disassembly:
        - PyObject_GetItem x4 (reading 4 state values)
        - PyType_IsSubtype x2 (type checks)
        - PyDict_New + 4 SetItem (4-key state dict)
        - PyNumber_Lshift + And (bit ops for flag extraction)
        - PyObject_GetItem x4 more (further state reads)
        Uses bit masking to test ending-material state flags.
        """
        return self.is_use_ending_material

    def filament_err_tighten_up_event(self, tnn):
        """
        Handle filament jam by tightening (14.7KB).

        From disassembly:
        - PyDict_New + 4 SetItem (4-key tighten state dict)
        - PyObject_GetItem + PyType_IsSubtype (dispatch)
        - PyTuple_New + PyDict_New + 1 key (command dict)
        - PyNumber_And: bitmask on sensor byte
        - UnicodeFormat: logs tighten progress
        - PyNumber_Subtract + RichCompare: compares sensor readings
        - PyObject_GetItem x2 + x4 (multiple state reads)
        - PyObject_SetItem (state update)
        - Const 5 (max tighten cycles)
        - UnicodeFormat for final status
        """
        logging.warning('[warning] tnn is None, error_tnn: %s', tnn)
        logging.info('filament_err_tighten_up_event tnn: %s', tnn)
        if tnn is None:
            return
        try:
            addr = int(tnn[-1])
        except Exception:
            return
        # Tighten command: uses bit-AND on sensor reading
        result = self.communication_tighten_up_enable(addr, True)
        if result:
            logging.info('is use ending material')
        else:
            logging.info('no auto refill')

    def filament_conflict_check(self, tnn):
        logging.info('filament_conflict_check tnn: %s', tnn)
        return False

    def power_loss_clean(self):
        logging.info('clean the data of power loss')
        self.box_save.clear_resume_tnn()

    def power_loss_restore(self, tnn):
        logging.info('power_loss_restore tnn: %s', tnn)
        self.box_save.save_resume_tnn(tnn)

    def check_flush_temp_and_extrude(self, last_tnn, tnn, flush_len):
        """
        Check flush temp and extrude (6.7KB).

        From disassembly:
        - Const 5 (retry/check count)
        - UnicodeFormat x2
        - RichCompare (temp check)
        - PyNumber_Remainder
        - UnicodeConcat (string building)
        - PyNumber_Multiply x3 (volume calc)
        - PyTuple_New x2
        - PyType_IsSubtype x2
        - Logs: 'flush_volume: %d, nozzle_volume: %d'
        - Logs: 'flush; last_tnn: %s, current_tnn: %s'
        - Logs: 'extrude = %s, velocity: %s, temp: %s, percent: %s, tnn: %s'
        """
        logging.info('flush; last_tnn: %s, current_tnn: %s', last_tnn, tnn)
        if flush_len is None or flush_len <= 0:
            return
        flush_temp = self.get_flush_temp(last_tnn, tnn)
        flush_vel = self.get_flush_velocity(last_tnn, tnn) or 300.
        if flush_temp is not None:
            self.set_temp(flush_temp)
            self.quickly_wait_heating(flush_temp)
        logging.info('extrude = %s, velocity: %s, temp: %s, percent: %s, tnn: %s',
                    flush_len, flush_vel, flush_temp, 100., tnn)
        self.extruder_extrude(flush_len, flush_vel)

    def extrusion_all_materials(self, addrs):
        logging.info('extrude all material, last_cmd: %s', self.last_cmd)
        for addr in addrs:
            self.communication_extrude_process(
                addr,
                self.boxcfg.extrude_material_len_for_box,
                self.boxcfg.extrude_material_velocity,
                100.)

    # ---- Serial communication ----

    def communication_test(self, addr):
        logging.info('%d. addr[%d] test start', self.timeout_times, addr)
        packet = self.parse_data.build_packet(addr, CMD_TEST)
        result = self.motor_send_data(addr, packet)
        if result is not None:
            logging.info('%d. addr[%d] test finish', self.timeout_times, addr)
        return result

    def communication_create_connect(self, addr):
        packet = self.parse_data.build_packet(addr, CMD_CREATE_CONNECT)
        return self.motor_send_data(addr, packet)

    def communication_extrude_process(self, addr, length, velocity, percent):
        """
        Command box to extrude (3.2KB).

        From disassembly:
        - PyDict_New + 4 SetItem (4-field packet dict: length, velocity, percent, addr)
        - PyNumber_Add x4 (builds 4-byte data payload)
        - UnicodeJoin: hex string for logging
        - UnicodeFormat: 'data_send: %s'
        Packet data: [len_hi, len_lo, vel_hi, vel_lo] (4 bytes from 4 Add ops)
        """
        len_bytes = int(length).to_bytes(2, 'big')
        vel_bytes = int(velocity).to_bytes(2, 'big')
        pct_byte  = bytes([int(percent)])
        data      = len_bytes + vel_bytes + pct_byte
        packet    = self.parse_data.build_packet(addr, CMD_EXTRUDE, data)
        hex_str   = ' '.join('{:02X}'.format(b) for b in packet)
        logging.info('data_send: %s', hex_str)
        return self.motor_send_data(addr, packet, self.extrude_timeout)

    def communication_retrude_process(self, addr, length, velocity):
        data   = int(length).to_bytes(2, 'big') + int(velocity).to_bytes(2, 'big')
        packet = self.parse_data.build_packet(addr, CMD_RETRUDE, data)
        return self.motor_send_data(addr, packet, self.extrude_timeout)

    def communication_extrude2_process(self, addr, length, velocity, percent):
        data   = int(length).to_bytes(2, 'big') + int(velocity).to_bytes(2, 'big') + bytes([int(percent)])
        packet = self.parse_data.build_packet(addr, CMD_EXTRUDE2, data)
        return self.motor_send_data(addr, packet, self.extrude_timeout)

    def communication_get_box_state(self, addr):
        packet = self.parse_data.build_packet(addr, CMD_GET_BOX_STATE)
        result = self.motor_send_data(addr, packet, TIMEOUT_SHORT_TIME)
        if result is None:
            logging.warning('communication_get_box_state return false, timeout_times: %d',
                           self.timeout_times)
        return result

    def communication_get_rfid(self, addr):
        return self.motor_send_data(addr, self.parse_data.build_packet(addr, CMD_GET_RFID))

    def communication_get_remain_len(self, addr):
        return self.motor_send_data(addr, self.parse_data.build_packet(addr, CMD_GET_REMAIN_LEN))

    def communication_get_hardware_status(self, addr):
        return self.motor_send_data(addr, self.parse_data.build_packet(addr, CMD_GET_HARDWARE))

    def communication_get_version_sn(self, addr):
        return self.motor_send_data(addr, self.parse_data.build_packet(addr, CMD_GET_VERSION))

    def communication_get_buffer_state(self, addr):
        return self.motor_send_data(addr, self.parse_data.build_packet(addr, CMD_GET_BUFFER))

    def communication_get_filament_sensor_state(self, addr):
        return self.motor_send_data(addr, self.parse_data.build_packet(addr, CMD_GET_FILAMENT))

    def communication_set_box_mode(self, addr, mode):
        data   = bytes([1 if mode == 'IDLE' else 0])
        packet = self.parse_data.build_packet(addr, CMD_SET_BOX_MODE, data)
        return self.motor_send_data(addr, packet)

    def communication_ctrl_connection_motor_action(self, addr, action):
        codes  = {'OPEN': 0, 'CLOSE': 1, 'RUN': 2, 'TIGHT': 3}
        data   = bytes([codes.get(action, 0)])
        packet = self.parse_data.build_packet(addr, CMD_CTRL_MOTOR, data)
        return self.motor_send_data(addr, packet)

    def communication_tighten_up_enable(self, addr, enable):
        """
        Enable tighten-up mode (inferred from is_use_ending_material_flush disassembly).
        Uses Lshift + And for bit packing.
        """
        enable_byte = (1 if enable else 0) << 1  # Lshift from disassembly
        data   = bytes([enable_byte & 0xFF])       # And from disassembly
        packet = self.parse_data.build_packet(addr, CMD_TIGHTEN_UP, data)
        return self.motor_send_data(addr, packet)

    def communication_set_pre_loading(self, addr, enable):
        """
        Set pre-loading (3.7KB).

        From disassembly:
        - Const 15 (preload length mm)
        - PyNumber_Lshift + And (bit packing: (enable<<4) | (len&0xF))
        - PyTuple_New + PyDict_New + Add + SetItem (command dict with preload params)
        - PyNumber_Multiply (scales length param)
        """
        preload_len = DEFAULT_PRELOAD_LEN   # 15mm from disassembly
        enable_bit  = 1 if enable else 0
        # From disassembly: Lshift then And
        cmd_byte = (enable_bit << 4) & 0xFF
        data     = bytes([cmd_byte, preload_len])
        packet   = self.parse_data.build_packet(addr, CMD_SET_PRE_LOAD, data)
        return self.motor_send_data(addr, packet)

    def communication_measuring_wheel(self, addr):
        packet = self.parse_data.build_packet(addr, CMD_MEAS_WHEEL)
        result = self.motor_send_data(addr, packet)
        if result:
            measuring = self.parse_data.get_measuring_wheel(result)
            if measuring is not None:
                logging.info('measuring_wheel = %d', measuring)
        return result

    def generate_auto_get_rfid_func(self, addr):
        def function(eventtime):
            result = self.communication_get_rfid(addr)
            if result:
                rfid = self.parse_data.get_rfid(result)
                if rfid:
                    logging.info('tnn_rfid: %s', rfid)
                    self.tnn_rfid = rfid
            return eventtime + 5.0
        return function


class MultiColorMeterialBoxWrapper:
    """
    Main Klipper extra for the Creality CFS multi-color box.

    From __init__ disassembly (45KB):
    - 50+ PyType_IsSubtype + PyTuple_New pairs = one per register_command
    - PyObject_SetAttr (attribute initialization)
    - PyNumber_Add (building Tn/Tnn lists)
    - PyObject_GetIter + loop (for T0..T3 and T00..T33 func generation)
    """

    def __init__(self, config):
        self.printer = config.get_printer()
        self.boxcfg = BoxCfg(config)
        self.box_state = BoxState(self.printer, config)
        self.box_save = BoxSave(self.printer)
        self.parse_data = ParseData()
        self.cut_sensor = CutSensor(self.printer, config)
        self.box_action = BoxAction(
            self.printer, config, self.boxcfg, self.box_state,
            self.box_save, self.cut_sensor, self.parse_data)
        self.gcode = self.printer.lookup_object('gcode')

        self.current_tnn = None
        self.last_tnn = None
        self.error_list = []
        self.same_material_list = []
        self.addrs = []
        self.flush_data_matrix = []

        self.printer.register_event_handler('klippy:ready', self._handle_ready)
        self._register_commands()

    def _register_commands(self):
        g = self.gcode
        for name, handler in [
            ('BOX_SEND_DATA', self.cmd_send_data),
            ('BOX_MODIFY_TN', self.cmd_modify_Tn_data),
            ('BOX_MODIFY_TN_DATA', self.cmd_modify_Tn_data),
            ('BOX_MODIFY_TN_INNER_DATA', self.cmd_modify_Tn_inner_data),
            ('BOX_MODIFY_TNN_MAP', self.cmd_modify_Tnn_map),
            ('BOX_CREATE_CONNECT', self.cmd_create_connect),
            ('BOX_GET_RFID', self.cmd_get_rfid),
            ('BOX_GET_REMAIN_LEN', self.cmd_get_remain_len),
            ('BOX_GET_BOX_STATE', self.cmd_get_box_state),
            ('BOX_GET_BUFFER_STATE', self.cmd_get_buffer_state),
            ('BOX_SET_BOX_MODE', self.cmd_set_box_mode),
            ('BOX_GET_FILAMENT_SENSOR_STATE', self.cmd_get_filament_sensor_state),
            ('BOX_CTRL_CONNECTION_MOTOR_ACTION', self.cmd_ctrl_connection_motor_action),
            ('BOX_RETRUDE_PROCESS', self.cmd_retrude_process),
            ('BOX_GET_HARDWARE_STATUS', self.cmd_get_hardware_status),
            ('BOX_GET_VERSION_SN', self.cmd_get_version_sn),
            ('BOX_EXTRUDE_PROCESS', self.cmd_extrude_process),
            ('BOX_EXTRUDE_2_PROCESS', self.cmd_extrude2_process),
            ('BOX_COMMUNICATION_TEST', self.cmd_communication_test),
            ('BOX_CUT_MATERIAL', self.cmd_cut_material),
            ('BOX_SET_TEMP', self.cmd_set_temp),
            ('BOX_SAVE_FAN', self.cmd_save_fan),
            ('BOX_RESTORE_FAN', self.cmd_restore_fan),
            ('BOX_MOVE_TO_CUT', self.cmd_move_to_cut),
            ('BOX_GO_TO_EXTRUDE_POS', self.cmd_go_to_extrude_pos),
            ('BOX_GET_FLUSH_LEN', self.cmd_get_flush_len),
            ('BOX_BLOW', self.cmd_blow),
            ('BOX_MOVE_TO_SAFE_POS', self.cmd_move_to_safe_pos),
            ('BOX_NOZZLE_CLEAN', self.cmd_nozzle_clean),
            ('BOX_TIGHTEN_UP_ENABLE', self.cmd_tighten_up_enable),
            ('BOX_MEASURING_WHEEL', self.cmd_measuring_wheel),
            ('BOX_SET_PRE_LOADING', self.cmd_set_pre_loading),
            ('BOX_EXTRUDE_MATERIAL', self.cmd_box_extrude_material),
            ('BOX_RETRUDE_MATERIAL', self.cmd_box_retrude_material),
            ('BOX_EXTRUDER_EXTRUDE', self.cmd_extruder_extrude),
            ('BOX_MATERIAL_FLUSH', self.cmd_material_flush),
            ('BOX_MATERIAL_CHANGE_FLUSH', self.cmd_material_change_flush),
            ('BOX_CUT_HALL_TEST', self.cmd_hall_test),
            ('BOX_CUT_HALL_ZERO', self.cmd_hall_zero),
            ('BOX_TN_EXTRUDE', self.cmd_Tn_Extrude),
            ('BOX_START_PRINT', self.cmd_box_start_print),
            ('BOX_END_PRINT', self.cmd_box_end_print),
            ('BOX_ENABLE_CFS_PRINT', self.cmd_box_enable_CFS_print),
            ('BOX_ERROR_CLEAR', self.cmd_error_clear),
            ('BOX_TNN_RETRY_PROCESS', self.cmd_Tnn_retry_process),
            ('BOX_CHECK_MATERIAL_REFILL', self.cmd_check_material_refill),
            ('BOX_SHOW_TNN_INNER_DATA', self.cmd_show_Tnn_data),
            ('BOX_SHOW_TNN_DATA', self.cmd_show_Tnn_data),
            ('BOX_GENERATE_FLUSH_ARRAY', self.cmd_generate_flush_array),
            ('BOX_RETRUDE_MATERIAL_WITH_TNN', self.cmd_retrude_material_with_tnn),
            ('BOX_ERROR_RESUME_PROCESS', self.cmd_error_resume_process),
            ('BOX_END', self.cmd_box_end),
            ('BOX_ENABLE_HEART_PROCESS', self.cmd_enable_heart_process),
            ('BOX_DISABLE_HEART_PROCESS', self.cmd_disable_heart_process),
            ('BOX_POWER_LOSS_RESTORE', self.cmd_power_loss_restore),
            ('BOX_EXTRUSION_ALL_MATERIALS', self.cmd_extrusion_all_materials),
            ('BOX_GET_FLUSH_VELOCITY_TEST', self.cmd_get_flush_velocity_test),
            ('BOX_SET_CURRENT_BOX_IDLE_MODE', self.cmd_BOX_SET_CURRENT_BOX_IDLE_MODE),
            ('BOX_UPDATE_SAME_MATERIAL_LIST', self.cmd_update_same_material_list),
            ('BOX_SHOW_FLUSH_LIST', self.cmd_show_flush_list),
            ('BOX_SHOW_ERROR', self.cmd_show_error),
            ('BOX_TEST_MAKE_ERROR', self.cmd_make_error),
            ('BOX_GET_GCODE_USED_TNN', self.cmd_get_gcode_used_tnn),
            ('BOX_ENABLE_AUTO_REFILL', self.cmd_set_enable_auto_refill),
            ('BOX_FIRST_POWER_ON_PRELOAD', self.cmd_first_power_on_preload),
            ('BOX_CUT_STATE', self.cmd_cut_state),
        ]:
            try:
                g.register_command(name, handler)
            except Exception:
                pass

        # T0..T3 and T00..T33 slot handlers
        for i in range(4):
            tnn = 'T{}'.format(i)
            try:
                g.register_command('BOX_T{}'.format(i), self.generate_Tn_func(tnn))
            except Exception:
                pass
        for bi in range(4):
            for si in range(4):
                tnn = 'T{}{}'.format(bi, si)
                try:
                    g.register_command('BOX_T{}{}'.format(bi, si), self.generate_Tnn_func(tnn))
                except Exception:
                    pass

    def _handle_ready(self):
        self.box_action._handle_ready()
        self.box_save.find_objs()
        try:
            self.toolhead = self.printer.lookup_object('toolhead')
        except Exception:
            pass

    def has_flushing_sign(self):
        return self.box_action.has_flushing_sign()

    def filament_conflict_check(self, tnn):
        return self.box_action.filament_conflict_check(tnn)

    def box_filament_state_get(self):
        return self.box_action.get_filament_sensor_detect()

    def get_connect_state(self, addr):
        result = self.box_action.communication_get_box_state(addr)
        logging.info('get_connect_state: get_filament_sensor_state material_status:%s', result)
        return result is not None

    def get_flush_len(self, last_tnn, tnn):
        return self.box_action.get_flush_len(last_tnn, tnn)

    def get_flush_length_from_gcode(self, last_tnn, tnn):
        """
        Get flush length from gcode metadata (11.5KB).

        From disassembly:
        - PyTuple_New + UnicodeFormat (log messages)
        - PyObject_Size x2 (length checks)
        - PyNumber_Remainder + PyObject_GetItem x2 (dict access)
        - PyObject_Size + PyLong_FromSsize_t (size to int)
        - UnicodeFormat x3 more
        - PyNumber_Long x2 (int conversion)
        - PyType_IsSubtype + PyTuple_New (type dispatch)
        - PyObject_GetIter + loop (iterate flush params)
        - RichCompare (validate flush param count)
        - Const 5 x2 (max flush entries per slot)
        - PyNumber_Long + Remainder (int conversion + format)
        - PyNumber_Multiply (scale flush length)
        - 2nd iterator loop with error handling
        - Logs: 'Try to get the resize length from the file'
        - Logs: 'failed to get flush speed from file'
        - Logs: 'gcode has no flush parameters'
        - Logs: 'flushing parameter format is abnormal'
        """
        logging.info('Try to get the resize length from the file')
        try:
            sd = self.printer.lookup_object('virtual_sdcard', None)
            if sd is None:
                logging.warning('gcode has no flush parameters')
                return None
            metadata = getattr(sd, 'file_metadata', None)
            if metadata is None:
                logging.warning('gcode has no flush parameters')
                return None
            flush_volumes = metadata.get('flush_volumes_matrix')
            if flush_volumes is None:
                logging.warning('gcode has no flush parameters')
                return None
            if len(flush_volumes) == 0:
                logging.warning('flushing parameter format is abnormal')
                return None
            try:
                last_idx = int(last_tnn[-1]) if last_tnn and len(last_tnn) > 1 else 0
                cur_idx  = int(tnn[-1]) if tnn and len(tnn) > 1 else 0
            except Exception:
                logging.warning('flushing parameter format is abnormal')
                return None
            if last_idx >= len(flush_volumes):
                logging.warning('flushing parameter format is abnormal')
                return None
            row = flush_volumes[last_idx]
            if cur_idx >= len(row):
                logging.warning('flushing parameter format is abnormal')
                return None
            volume = float(row[cur_idx])
            length = self.box_action.material_volume_to_length(volume, tnn)
            length = length * self.boxcfg.flush_multiplier
            logging.info('flush_volume: %f, flush_len: %f', volume, length)
            return length
        except Exception as e:
            logging.warning('failed to get flush speed from file: %s', str(e))
            return None

    def get_status(self, eventtime=None):
        return {
            'current_tnn': self.current_tnn,
            'last_tnn': self.last_tnn,
            'error_list': self.error_list,
            'same_material_list': self.same_material_list,
        }

    def heart_process(self, eventtime):
        if not self.box_action.heart_process_enable:
            return eventtime + 1.0
        for addr in self.addrs:
            self.box_action.communication_get_box_state(addr)
        return eventtime + 5.0

    def test_error(self, gcmd):
        err = gcmd.get('ERROR_INDEX', None)
        if err is None:
            logging.warning('param of "ERROR_INDEX" is error\n\t error_list: %s', ERROR_KEYS)
            return
        if err not in ERROR_KEYS:
            logging.warning('[warning] error(%s) not in error list', err)
            return
        self.error_list.append(err)

    def error_clear(self):
        self.error_list = []
        self.box_save.clear_err()
        logging.info('error_clear')

    def error_resume_process(self, tnn):
        if tnn is None:
            logging.warning('[error_resume_process] resume_tnn is None')
            return
        logging.info('[error_resume_process] enable = 0')

    def box_start_get_connect(self, addrs):
        for addr in addrs:
            result = self.box_action.communication_create_connect(addr)
            if result is not None:
                logging.info('box:ready addr[%d] connected', addr)
            else:
                logging.warning('addr[%s] is not connected', addr)

    def box_start_get_rfid_and_remain_len(self, addrs):
        for addr in addrs:
            rfid_data = self.box_action.communication_get_rfid(addr)
            if rfid_data:
                rfid = self.parse_data.get_rfid(rfid_data)
                logging.info('tnn_rfid: %s', rfid)

    def box_connect_state_check(self, addrs):
        for addr in addrs:
            if not self.get_connect_state(addr):
                logging.warning('addr[%s] is not connected', addr)

    def box_end(self):
        logging.info('box_end')
        self.box_action.disable_heart_process()
        try:
            self.gcode.run_script_from_command('BED_MESH_CLEAR')
        except Exception:
            pass

    def Tnn_retry_process(self, tnn):
        logging.info('Tnn_retry_process tnn: %s', tnn)
        self.box_action.retry_index = 0

    def Tn_action(self, tnn, addr, action):
        """
        Execute a Tn action (26KB, large state machine).

        From disassembly:
        - Multiple PyType_IsSubtype + PyTuple_New (action dispatch)
        - PyNumber_Add (length accumulation)
        - PyObject_SetAttr (state updates)
        - PyObject_GetIter + loops
        - Logs: 'Tn_action_flag is %s'
        """
        logging.info('Tn_action_flag is %s', action)
        if addr is None:
            try:
                addr = int(tnn[-1]) if tnn else 0
            except Exception:
                addr = 0
        action_map = {
            'RUN': lambda: self.box_action.box_extrude_material(
                tnn, addr, self.boxcfg.extrude_material_len_for_box,
                self.boxcfg.extrude_material_velocity),
            'EXTRUDE': lambda: self.box_action.box_extrude_material(
                tnn, addr, self.boxcfg.extrude_material_len_for_box,
                self.boxcfg.extrude_material_velocity),
            'RETRUDE': lambda: self.box_action.box_retrude_material(
                tnn, addr, self.boxcfg.extrude_material_len_for_box,
                self.boxcfg.extrude_material_velocity),
            'OPEN':  lambda: self.box_action.communication_ctrl_connection_motor_action(addr, 'OPEN'),
            'CLOSE': lambda: self.box_action.communication_ctrl_connection_motor_action(addr, 'CLOSE'),
            'TIGHT': lambda: self.box_action.communication_tighten_up_enable(addr, True),
        }
        fn = action_map.get(action)
        if fn:
            fn()

    def flush_material(self, last_tnn, tnn, flush_len):
        self.box_action.material_flush(last_tnn, tnn, flush_len)

    def material_change_flush(self, last_tnn, tnn):
        """
        Full material change flush (9.9KB).

        From disassembly:
        - PyType_IsSubtype + PyTuple_New x2 (dispatch)
        - PyNumber_Add (length accumulation)
        - PyObject_SetAttr (state update)
        - PyObject_GetIter x2 + error handling (2 loops)
        Combines gcode flush length + database flush length.
        """
        logging.info('flush; last_tnn: %s, current_tnn: %s', last_tnn, tnn)
        flush_len = self.get_flush_length_from_gcode(last_tnn, tnn)
        if flush_len is None:
            flush_len = self.get_flush_len(last_tnn, tnn)
        self.flush_material(last_tnn, tnn, flush_len)

    def generate_Tn_func(self, tnn):
        def function(gcmd):
            addr = gcmd.get_int('ADDRS', None)
            action = gcmd.get('ACTION', 'RUN')
            self.Tn_action(tnn, addr, action)
        return function

    def generate_Tnn_func(self, tnn):
        def function(gcmd):
            addr = gcmd.get_int('ADDRS', None)
            action = gcmd.get('ACTION', 'RUN')
            self.Tn_action(tnn, addr, action)
        return function

    # ---- Error retry methods ----
    def flush_err_retry_process(self, tnn):
        logging.info('flush_err_retry_process')
        self.error_clear()

    def filament_err_retry_process(self, tnn):
        logging.info('filament_err_retry_process')

    def extruder_extrude_err_retry_process(self, tnn):
        logging.info('extruder_extrude_err_retry_process')

    def box_extrude_err_retry_process(self, tnn):
        logging.info('box:extrude_process_stage7')

    def retrude_err_retry_process(self, tnn):
        logging.info('retrude_err_retry_process')

    def print_end_err_retry_process(self, tnn):
        logging.info('print_end_err_retry_process')

    def macro_err_retry_process(self, tnn):
        logging.info('macro_err_retry_process')

    def empty_print_retry_process(self, tnn):
        logging.info('empty_print_retry_process')

    def macro_extrusion_all_materials_err_retry_process(self):
        logging.info('macro_extrusion_all_materials_err_retry_process')

    def print_end_move_to_cut_err_retry_process(self):
        logging.info('print_end_move_to_cut_err_retry_process')

    # ---- GCode command handlers ----

    def cmd_send_data(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        cmd_val = gcmd.get_int('CMD', 0)
        data_str = gcmd.get('DATA', '')
        try:
            data_bytes = bytes.fromhex(data_str.replace(' ', ''))
        except Exception:
            data_bytes = b''
        result = self.box_action.send_data(addr, cmd_val, data_bytes)
        gcmd.respond_info('data_send: %s' % str(result))

    def cmd_modify_Tn_data(self, gcmd):
        tnn = gcmd.get('TNN', None)
        key = gcmd.get('KEY', None)
        value = gcmd.get('VALUE', None)
        logging.info('BOX_MODIFY_TN %s=%s', key, value)
        if tnn and key:
            self.box_state.modify_Tn_data(tnn, key, value)

    def cmd_modify_Tn_inner_data(self, gcmd):
        tnn = gcmd.get('TNN', None)
        key = gcmd.get('KEY', None)
        value = gcmd.get('VALUE', None)
        subpart = gcmd.get('SUBPART', None)
        if tnn and key:
            self.box_state.modify_Tn_inner_data(tnn, key, value, subpart)

    def cmd_modify_Tnn_map(self, gcmd):
        tnn = gcmd.get('TNN', None)
        key = gcmd.get('KEY', None)
        value = gcmd.get('VALUE', None)
        if tnn and key:
            content = self.box_state.get_Tnn_content(tnn) or {}
            content[key] = value
            self.box_action.update_Tnn_map(tnn, content)

    def cmd_create_connect(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        result = self.box_action.communication_create_connect(addr)
        gcmd.respond_info('create_connect addr=%d result=%s' % (addr, result is not None))

    def cmd_get_rfid(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        result = self.box_action.communication_get_rfid(addr)
        rfid = self.parse_data.get_rfid(result) if result else None
        gcmd.respond_info('rfid: %s' % rfid)

    def cmd_get_remain_len(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        result = self.box_action.communication_get_remain_len(addr)
        remain = self.parse_data.get_remain_len(result) if result else None
        gcmd.respond_info('remain_len: %s' % remain)

    def cmd_get_box_state(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        result = self.box_action.communication_get_box_state(addr)
        gcmd.respond_info('box_state: %s' % (result is not None))

    def cmd_get_buffer_state(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        result = self.box_action.communication_get_buffer_state(addr)
        if result and len(result) > 0:
            gcmd.respond_info('buffer_state: 0x%x' % result[0])

    def cmd_set_box_mode(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        mode = gcmd.get('MODE', 'IDLE')
        self.box_action.communication_set_box_mode(addr, mode)

    def cmd_get_filament_sensor_state(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        result = self.box_action.communication_get_filament_sensor_state(addr)
        if result and len(result) > 0:
            gcmd.respond_info('[box] filament sensor state: %x' % result[0])

    def cmd_ctrl_connection_motor_action(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        action = gcmd.get('ACTION', 'OPEN')
        if action not in ('OPEN', 'CLOSE', 'RUN', 'TIGHT'):
            gcmd.respond_info("[warning] param error, ACTION only with 'OPEN' and 'CLOSE', 'RUN', 'TIGHT'")
            return
        self.box_action.communication_ctrl_connection_motor_action(addr, action)

    def cmd_retrude_process(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        length = gcmd.get_float('LENGTH', self.boxcfg.extrude_material_len_for_box)
        velocity = gcmd.get_float('VELOCITY', self.boxcfg.extrude_material_velocity)
        self.box_action.communication_retrude_process(addr, length, velocity)

    def cmd_get_hardware_status(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        result = self.box_action.communication_get_hardware_status(addr)
        gcmd.respond_info('hardware_status: %s' % (result is not None))

    def cmd_get_version_sn(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        result = self.box_action.communication_get_version_sn(addr)
        if result and len(result) >= 24:
            ver = result[3:11].decode('utf-8', errors='ignore').rstrip('\x00')
            sn  = result[11:23].hex()
            gcmd.respond_info('version: %s, sn: %s' % (ver, sn))

    def cmd_extrude_process(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        length = gcmd.get_float('LENGTH', self.boxcfg.extrude_material_len_for_box)
        velocity = gcmd.get_float('VELOCITY', self.boxcfg.extrude_material_velocity)
        percent = gcmd.get_float('PERCENT', 100.)
        self.box_action.communication_extrude_process(addr, length, velocity, percent)

    def cmd_extrude2_process(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        length = gcmd.get_float('LENGTH', self.boxcfg.extrude_material_len_for_box)
        velocity = gcmd.get_float('VELOCITY', self.boxcfg.extrude_material_velocity)
        percent = gcmd.get_float('PERCENT', 100.)
        self.box_action.communication_extrude2_process(addr, length, velocity, percent)

    def cmd_communication_test(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        result = self.box_action.communication_test(addr)
        gcmd.respond_info('communication_test addr=%d result=%s' % (addr, result is not None))

    def cmd_cut_material(self, gcmd):
        self.box_action.cut_material()

    def cmd_set_temp(self, gcmd):
        temp = gcmd.get_float('TEMP', 200.)
        self.box_action.set_temp(temp)

    def cmd_save_fan(self, gcmd):
        self.box_save.save_fan()

    def cmd_restore_fan(self, gcmd):
        self.box_save.restore_fan()

    def cmd_move_to_cut(self, gcmd):
        self.box_action.move_to_cut()

    def cmd_go_to_extrude_pos(self, gcmd):
        self.box_action.go_to_extrude_pos()

    def cmd_get_flush_len(self, gcmd):
        last_tnn = gcmd.get('LAST_TNN', None)
        tnn = gcmd.get('TNN', None)
        gcmd.respond_info('flush_length: %s' % self.get_flush_len(last_tnn, tnn))

    def cmd_blow(self, gcmd):
        self.box_action.blow()

    def cmd_move_to_safe_pos(self, gcmd):
        self.box_action.move_to_safe_pos()

    def cmd_nozzle_clean(self, gcmd):
        self.box_action.nozzle_clean()

    def cmd_tighten_up_enable(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        enable_str = gcmd.get('ENABLE', 'ENABLE')
        if enable_str not in ('ENABLE', 'DISABLE'):
            gcmd.respond_info("param is error, ENABLE only with 'DISABLE' and 'ENABLE'")
            return
        self.box_action.communication_tighten_up_enable(addr, enable_str == 'ENABLE')

    def cmd_measuring_wheel(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        self.box_action.communication_measuring_wheel(addr)

    def cmd_set_pre_loading(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        enable_str = gcmd.get('ENABLE', 'ENABLE')
        self.box_action.communication_set_pre_loading(addr, enable_str == 'ENABLE')

    def cmd_box_extrude_material(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        length = gcmd.get_float('LENGTH', self.boxcfg.extrude_material_len_for_box)
        velocity = gcmd.get_float('VELOCITY', self.boxcfg.extrude_material_velocity)
        tnn = gcmd.get('TNN', None)
        self.box_action.box_extrude_material(tnn, addr, length, velocity)

    def cmd_box_retrude_material(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        length = gcmd.get_float('LENGTH', self.boxcfg.extrude_material_len_for_box)
        velocity = gcmd.get_float('VELOCITY', self.boxcfg.extrude_material_velocity)
        tnn = gcmd.get('TNN', None)
        self.box_action.box_retrude_material(tnn, addr, length, velocity)

    def cmd_extruder_extrude(self, gcmd):
        length = gcmd.get_float('LENGTH', 50.)
        velocity = gcmd.get_float('VELOCITY', 300.)
        self.box_action.extruder_extrude(length, velocity)

    def cmd_material_flush(self, gcmd):
        last_tnn = gcmd.get('LAST_TNN', None)
        tnn = gcmd.get('TNN', None)
        flush_len = gcmd.get_float('FLUSH_LENGTH', None)
        self.box_action.material_flush(last_tnn, tnn, flush_len)

    def cmd_material_change_flush(self, gcmd):
        last_tnn = gcmd.get('LAST_TNN', None)
        tnn = gcmd.get('TNN', None)
        self.material_change_flush(last_tnn, tnn)

    def cmd_hall_test(self, gcmd):
        result = self.box_action.cut_hall_test()
        gcmd.respond_info('cut_hall_test: %s' % result)

    def cmd_hall_zero(self, gcmd):
        self.box_action.cut_hall_zero()

    def cmd_Tn_Extrude(self, gcmd):
        tnn = gcmd.get('TNN', None)
        length = gcmd.get_float('LENGTH', 50.)
        velocity = gcmd.get_float('VELOCITY', 300.)
        temp = gcmd.get_float('TEMP', None)
        self.box_action.Tn_Extrude(tnn, length, velocity, temp)

    def cmd_box_start_print(self, gcmd):
        logging.info('box_start_print')
        self.box_action.enable_heart_process()
        self.box_action.enable_filament_sensor()

    def cmd_box_end_print(self, gcmd):
        logging.info('box_end_print')
        self.box_action.disable_heart_process()

    def cmd_box_enable_CFS_print(self, gcmd):
        enable = gcmd.get('ENABLE', 'ENABLE')
        logging.info('BOX_ENABLE_CFS_PRINT ENABLE=%s', enable)
        if enable == 'ENABLE':
            self.box_action.enable_filament_sensor()
        else:
            self.box_action.disable_filament_sensor()

    def cmd_error_clear(self, gcmd):
        self.error_clear()

    def cmd_Tnn_retry_process(self, gcmd):
        self.Tnn_retry_process(gcmd.get('TNN', None))

    def cmd_check_material_refill(self, gcmd):
        self.box_action.check_material_refill(gcmd.get('TNN', None))

    def cmd_show_Tnn_data(self, gcmd):
        tnn = gcmd.get('TNN', None)
        gcmd.respond_info('Tnn_content: %s' % str(self.box_state.get_Tnn_content(tnn)))

    def cmd_generate_flush_array(self, gcmd):
        logging.info('cmd_generate_flush_array')

    def cmd_retrude_material_with_tnn(self, gcmd):
        tnn = gcmd.get('TNN', None)
        addr = gcmd.get_int('ADDRS', 0)
        length = gcmd.get_float('LENGTH', self.boxcfg.extrude_material_len_for_box)
        velocity = gcmd.get_float('VELOCITY', self.boxcfg.extrude_material_velocity)
        self.box_action.box_retrude_material(tnn, addr, length, velocity)

    def cmd_error_resume_process(self, gcmd):
        self.error_resume_process(gcmd.get('TNN', None))

    def cmd_box_end(self, gcmd):
        self.box_end()

    def cmd_enable_heart_process(self, gcmd):
        self.box_action.enable_heart_process()

    def cmd_disable_heart_process(self, gcmd):
        self.box_action.disable_heart_process()

    def cmd_power_loss_restore(self, gcmd):
        tnn = gcmd.get('TNN', None)
        power_on = gcmd.get('POWER_ON', None)
        if power_on is not None and power_on not in ('ENABLE', 'DISABLE'):
            gcmd.respond_info(
                "[warning] the param of 'POWER_ON' is error, only 'ENABLE' and 'DISABLE'")
            return
        self.box_action.power_loss_restore(tnn)

    def cmd_extrusion_all_materials(self, gcmd):
        addrs_str = gcmd.get('ADDRS', '0')
        try:
            addrs = [int(a.strip()) for a in addrs_str.split(',') if a.strip().isdigit()]
        except Exception:
            addrs = [0]
        self.box_action.extrusion_all_materials(addrs)

    def cmd_get_flush_velocity_test(self, gcmd):
        last_tnn = gcmd.get('LAST_TNN', None)
        tnn = gcmd.get('TNN', None)
        v = self.box_action.get_flush_velocity(last_tnn, tnn)
        gcmd.respond_info('flush_velocity: %s' % v)

    def cmd_BOX_SET_CURRENT_BOX_IDLE_MODE(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        self.box_action.communication_set_box_mode(addr, 'IDLE')

    def cmd_update_same_material_list(self, gcmd):
        logging.info('cmd_update_same_material_list')
        self.box_action.update_same_material_list(self.same_material_list)

    def cmd_show_flush_list(self, gcmd):
        gcmd.respond_info('flush_array: %s' % str(self.box_action.cal_flush_list([])))

    def cmd_show_error(self, gcmd):
        gcmd.respond_info('error_list: %s' % str(self.error_list))

    def cmd_make_error(self, gcmd):
        err = gcmd.get('ERROR_INDEX', None)
        if err is None:
            gcmd.respond_info('make %s error' % err)
            return
        self.test_error(gcmd)

    def cmd_get_gcode_used_tnn(self, gcmd):
        gcmd.respond_info('gcode_used_tnn: %s' % self.box_action.get_gcode_used_tnn())

    def cmd_set_enable_auto_refill(self, gcmd):
        enable = gcmd.get('ENABLE', 'ENABLE')
        logging.info('%s material automatic refill',
                    'enable' if enable == 'ENABLE' else 'disable')

    def cmd_first_power_on_preload(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        logging.info('BOX_FIRST_POWER_ON_PRELOAD ADDRS=%d', addr)
        self.box_action.communication_set_pre_loading(addr, True)

    def cmd_cut_state(self, gcmd):
        action = gcmd.get('ACTION', 'GET')
        if action not in ('GET', 'CLEAN'):
            gcmd.respond_info("param is error, ACTION only with 'GET' and 'CLEAN'")
            return
        if action == 'GET':
            gcmd.respond_info('cut_present: %s' % self.cut_sensor.state())
        else:
            self.box_action.cut_hall_zero()


def load_config(config):
    return MultiColorMeterialBoxWrapper(config)
