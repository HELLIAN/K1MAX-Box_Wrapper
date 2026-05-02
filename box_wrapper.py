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
    '000000': '黑色',
    '1B04AE': '深蓝',
    '26EEEE': '天蓝',
    '3DDF57': '中绿',
    '6C84FF': '钴蓝',
    '66DBA2': '浅绿',
    '72A530': '草绿',
    '7A92AC': '灰色',
    '8A43FF': '紫色',
    '9CFF4F': '嫩粉红',
    '9EA7AE': '深灰',
    'B2A1E1': '淡紫色',
    'BA552A': '褐色',
    'CE58F8': '蓝紫',
    'F4E076': '浅黄',
    'FF1E1E': '大红',
    'FF37AF': '粉色',
    'FF614B': '橙红',
    'FF8B1F': '桔黄',
    'FF97E1': '嫩粉红',
    'FFA800': '中黄',
    'FFF014': '柠檬黄',
    'FFFFFF': '白色',
    '00A3FF': '蓝色',
}

TIMEOUT_SHORT_TIME  = 3.0
TIMEOUT_LONG_TIME   = 10.0
TIMEOUT_LONGER_TIME = 30.0
TIMEOUT_MAX         = 60.0

# Error key constants
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
    'key843': 'rfid is error',
    'key844': 'pneumatic joint abnormal, may collapse',
    'key845': 'nozzle is blocked',
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
    'key_retrude_err1': 'retrude error 1',
    'key_retrude_err2': 'retrude error 2',
    'key_retrude_err3': 'retrude error 3',
    'key_retrude_err4': 'retrude error 4',
    'key_retrude_err6': 'retrude error 6',
    'key_extrude_err1': 'extrude error 1',
    'key_extrude_err2': 'extrude error 2',
    'key_extrude_err3': 'extrude error 3',
    'key_extrude_err4': 'extrude error 4',
    'key_extrude_err5': 'extrude error 5',
    'key_filament_err': 'filament error',
    'key_material_err': 'material error',
    'key_sensor_err': 'sensor error',
    'key_params_err': 'params error',
    'key_state_err': 'state error',
    'key_speed_err': 'speed error',
    'key_joint_err': 'joint error',
    'key_timeout': 'timeout',
    'key_buffer_err': 'buffer error',
    'key_cutter_err': 'cutter error',
    'key_eeprom_err': 'eeprom error',
    'key_enwind_err': 'enwind error',
    'key_nozzle_blocked_err': 'nozzle blocked error',
    'key_measuring_wheel_err': 'measuring wheel error',
    'key_left_rfid_card_err': 'left rfid card error',
    'key_right_rfid_card_err': 'right rfid card error',
    'key_rfid_err': 'rfid error',
    'key_load_err': 'load error',
    'key_cut_pos_err': 'cut position error',
    'key_dry_and_humidity_err': 'dry and humidity error',
}


class error(Exception):
    def __init__(self, msg):
        super().__init__(msg)
        self.msg = msg


class ParseData:
    """Parses raw serial data packets from the box hardware."""

    def __init__(self):
        self.head = 0xAA
        self.tail = 0x55

    def get_cmd_num(self, data):
        if data is None:
            return None
        try:
            return data[2] if len(data) > 2 else None
        except Exception:
            return None

    def parse_num_to_byte(self, num, length=1, byteorder='big'):
        return num.to_bytes(length, byteorder=byteorder)

    def parse_num_string_to_byte(self, num_string, length=1, byteorder='big'):
        try:
            num = int(num_string)
            return self.parse_num_to_byte(num, length, byteorder)
        except Exception:
            return b'\x00' * length

    def get_key_from_value(self, d, value):
        for k, v in d.items():
            if v == value:
                return k
        return None

    def get_rfid(self, data):
        if data is None:
            return None
        try:
            # Extract RFID bytes and format as hex pairs
            rfid_bytes = data[4:20]
            hex_pairs = ['{:02X}'.format(b) for b in rfid_bytes]
            return ''.join(hex_pairs)
        except Exception:
            return None

    def get_remain_len(self, data):
        if data is None:
            return None
        try:
            remain_len_values = struct.unpack_from('>I', data, 4)[0]
            return remain_len_values
        except Exception:
            return None

    def get_measuring_wheel(self, data):
        if data is None:
            return None
        try:
            data_hex = struct.unpack_from('>I', data, 4)[0]
            logging.info('[get_measuring_wheel] data_hex: 0x%x, data:%s', data_hex, data)
            return data_hex
        except Exception:
            return None


class BoxCfg:
    """Holds all configuration parameters for the box."""

    def __init__(self, config):
        self.cut_pos_x = config.getfloat('cut_pos_x', 0.)
        self.cut_pos_y = config.getfloat('cut_pos_y', 0.)
        self.pre_cut_pos_x = config.getfloat('pre_cut_pos_x', 0.)
        self.pre_cut_pos_y = config.getfloat('pre_cut_pos_y', 0.)
        self.safe_pos_x = config.getfloat('safe_pos_x', 0.)
        self.safe_pos_y = config.getfloat('safe_pos_y', 0.)
        self.extrude_pos_x = config.getfloat('extrude_pos_x', 0.)
        self.extrude_pos_y = config.getfloat('extrude_pos_y', 0.)
        self.has_extrude_pos = config.getint('has_extrude_pos', 0)
        self.clean_velocity = config.getfloat('clean_velocity', 10000.)
        self.clean_pos_min_x = config.getfloat('clean_pos_min_x', 0.)
        self.clean_pos_min_y = config.getfloat('clean_pos_min_y', 0.)
        self.clean_pos_max_x = config.getfloat('clean_pos_max_x', 0.)
        self.clean_pos_max_y = config.getfloat('clean_pos_max_y', 0.)
        self.clean_left_pos_x = config.getfloat('clean_left_pos_x', 0.)
        self.clean_left_pos_y = config.getfloat('clean_left_pos_y', 0.)
        self.clean_right_pos_x = config.getfloat('clean_right_pos_x', 0.)
        self.clean_right_pos_y = config.getfloat('clean_right_pos_y', 0.)
        self.clean_pos_middle_y = config.getfloat('clean_pos_middle_y', 0.)
        self.trigger_pos = config.getfloat('trigger_pos', 0.)
        self.nest_speed = config.getfloat('nest_speed', 6000.)
        self.max_tube_length = config.getfloat('max_tube_length', 800.)
        self.box_first_clean_length = config.getfloat('box_first_clean_length', 100.)
        self.box_need_clean_length = config.getfloat('box_need_clean_length', 50.)
        self.box_need_clean_length_max = config.getfloat('box_need_clean_length_max', 200.)
        self.buffer_empty_len = config.getfloat('buffer_empty_len', 100.)
        self.cut_velocity = config.getfloat('cut_velocity', 3000.)
        self.cut_push_rod = config.getfloat('cut_push_rod', 5.)
        self.switch_pin = config.get('switch_pin', None)


class BoxState:
    """Manages the state of filament slots (Tn data, Tnn map, etc.)."""

    def __init__(self, printer, config):
        self.printer = printer
        self.tn_save_data_path = 'creality/userdata/box/tn_data.json'
        self.tn_save_data = {}
        self.tn_save_data_parts = []
        self.data_upper_parts = []
        self.inner_data_parts = []
        self.inner_data_upper_parts = []
        self.Tnn_map = {}
        self.e_err = None
        self.state_init()

    def state_init(self):
        self.Tnn_map = {}
        self.tn_save_data = {}

    def generate_Tn_map(self, num):
        result = {}
        for i in range(num):
            result['T{}'.format(i)] = None
        return result

    def generate_Tnn_content(self, tnn):
        return {
            'color': None,
            'material': None,
            'tnn': tnn,
            'rfid': None,
        }

    def generate_Tnn_map(self, num):
        result = {}
        for i in range(num):
            key = 'T{}{}'.format(i // 4, i % 4) if num > 4 else 'T0{}'.format(i)
            result[key] = self.generate_Tnn_content(key)
        return result

    def generate_Tn_data(self, num):
        data = {}
        for i in range(num):
            data['T{}'.format(i)] = {
                'rfid': None,
                'material': None,
                'color': None,
                'remain_len': None,
            }
        return data

    def generate_Tn_inner_data(self, num):
        data = {}
        for i in range(num):
            data['T{}'.format(i)] = {
                'state': None,
                'enable': False,
                'tnn_map': None,
                'last_cmd': None,
            }
        return data

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

    def get_Tn_inner_data(self, part, tnn=None):
        if part is None:
            logging.warning('get Tn inner data error, has no part')
            return None
        return self.tn_save_data.get(part)

    def modify_Tn_inner_data(self, part, key, value, subpart=None):
        if part is None:
            logging.warning('change Tn inner data error, has no part(%s)', part)
            return
        logging.info('Tn_inner_data[%s][%s][%s]: %s', part, key, subpart, value)

    def get_Tnn_content(self, tnn):
        return self.Tnn_map.get(tnn)

    def get_Tnn_map(self):
        return copy.deepcopy(self.Tnn_map)

    def sync_tn_data(self):
        try:
            if os.path.exists(self.tn_save_data_path):
                with open(self.tn_save_data_path, 'r') as f:
                    self.tn_save_data = json.load(f)
        except Exception as e:
            logging.warning('sync_tn_data error: %s', str(e))

    def generate_tn_save_data(self):
        return copy.deepcopy(self.tn_save_data)

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
        try:
            os.makedirs(os.path.dirname(self.tn_save_data_path), exist_ok=True)
            with open(self.tn_save_data_path, 'w') as f:
                json.dump(self.tn_save_data, f)
        except Exception as e:
            logging.warning('update_tn_save_data error: %s', str(e))

    def update_same_material_list(self, same_material_list):
        logging.info('same_material_list: %s, same_tnn_list: %s',
                     same_material_list, [])

    def e_err_set(self, err):
        self.e_err = err

    def clear_e_err(self):
        self.e_err = None


class BoxSave:
    """Handles saving/restoring printer state (fan speed, accel, error info)."""

    def __init__(self, printer):
        self.printer = printer
        self.fan0_last_value = 0.
        self.fan2_last_value = 0.
        self.resume_tnn = None
        self.resume_flag = False
        self.err_tnn = None

    def find_objs(self):
        self.gcode = self.printer.lookup_object('gcode')

    def save_fan(self):
        try:
            fan0 = self.printer.lookup_object('output_pin fan0', None)
            if fan0 is not None:
                self.fan0_last_value = fan0.last_value
            fan2 = self.printer.lookup_object('output_pin_fan2', None)
            if fan2 is not None:
                self.fan2_last_value = fan2.last_value
        except Exception as e:
            logging.warning('[box] do not define \'output_pin fan0\': %s', str(e))

    def restore_fan(self):
        try:
            self.gcode.run_script_from_command(
                'SET_PIN PIN=fan0 VALUE=%.2f' % self.fan0_last_value)
            self.gcode.run_script_from_command(
                'SET_PIN PIN=fan2 VALUE=%.2f' % self.fan2_last_value)
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
        logging.info('clear resume_flag')

    def get_err(self):
        return self.err_tnn


class CutSensor:
    """Manages the filament cutting sensor (button/switch)."""

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
        self.cut_present = state
        logging.info('[box] cut sensor %s', 'detected' if state else 'not detected')

    def state(self):
        return self.cut_present


class BoxAction:
    """Core action handler: communicates with the box, manages extrusion/retraction."""

    def __init__(self, printer, config, boxcfg, boxstate, boxsave, cut_sensor, parse_data):
        self.printer = printer
        self.boxcfg = boxcfg
        self.box_state = boxstate
        self.box_save = boxsave
        self.cut = cut_sensor
        self.parse_data = parse_data
        self.reactor = printer.get_reactor()
        self._serial = None
        self.addr_manager_table_mb = None
        self.current_tnn = None
        self.last_tnn = None
        self.last_cmd = None
        self.error_list = []
        self.heart_process_enable = False
        self.flushing_sign = False
        self.extrude_process_stage7_flag = False
        self.extrude_process_ret_state = None
        self.extrude_process_stage7_ret = None
        self.material_auto_refill_flag = False
        self.is_use_ending_material = False
        self.extrude_timeout = TIMEOUT_LONG_TIME
        self.cmd_timeout = TIMEOUT_LONG_TIME
        self.timeout_times = 0
        self.retry_index = 0
        self.release_succeed_num = 0
        self.release_failed_num = 0
        self.cut_succeed_num = 0
        self.cut_cycle_index = 0
        self.auto_get_rfid_addr = None
        self.lock = threading.Lock()

    def find_objs(self):
        self.gcode = self.printer.lookup_object('gcode')
        self.toolhead = self.printer.lookup_object('toolhead')
        self.pause_resume = self.printer.lookup_object('pause_resume', None)
        try:
            self._serial = self.printer.lookup_object('serial_485')
        except Exception:
            logging.warning('the bus of box is not configured, it is the name of serial_485, '
                           'such as [serial_485 serial485] and bus: serial485')

    def _handle_ready(self):
        logging.info('box:ready')
        self.find_objs()
        self.box_state.sync_tn_data()
        self.printer.register_event_handler('klippy:shutdown', self._handle_shutdown)

    def _handle_shutdown(self):
        logging.info('klippy:shutdown')

    def enable_filament_sensor(self):
        try:
            self.gcode.run_script_from_command(
                'SET_FILAMENT_SENSOR SENSOR=filament_sensor ENABLE=1')
        except Exception:
            pass

    def disable_filament_sensor(self):
        try:
            self.gcode.run_script_from_command(
                'SET_FILAMENT_SENSOR SENSOR=filament_sensor ENABLE=0')
        except Exception:
            pass

    def enable_heart_process(self):
        self.heart_process_enable = True

    def disable_heart_process(self):
        self.heart_process_enable = False

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

    def motor_send_data(self, addr, data_bytes):
        if self._serial is None:
            return None
        try:
            return self._serial.send_data(addr, data_bytes)
        except Exception as e:
            logging.warning('motor_send_data error: %s', str(e))
            return None

    def send_data(self, addr, data_bytes, timeout=None):
        if timeout is None:
            timeout = self.cmd_timeout
        result = self.motor_send_data(addr, data_bytes)
        logging.info('data_send:%s recv_result:%s', data_bytes, result)
        return result

    def ret_parse_process(self, data, expected_cmd):
        if data is None:
            return None
        cmd_num = self.parse_data.get_cmd_num(data)
        if cmd_num != expected_cmd:
            logging.warning('%d.get return data(0x%x) error, send data: 0x%x',
                           self.timeout_times, cmd_num or 0, expected_cmd)
            return None
        return data

    def process_msg(self, data):
        if data is None:
            return
        logging.info('msg_data: %s', data)

    def timeout_process(self, timeout=None):
        if timeout is None:
            timeout = self.cmd_timeout
        self.timeout_times += 1
        logging.warning('%d.timeout, TIMEOUT=%.2f, send data: 0x%x',
                       self.timeout_times, timeout, 0)

    def update_state_process(self, data):
        logging.info('update_state_process, data: %s', data)

    def check_connect(self, addr):
        if addr is None:
            logging.warning('[error] addr: %s', addr)
            return False
        return True

    def check_rfid_valid(self, rfid):
        if rfid is None:
            return False
        return len(rfid) > 0

    def rfid_check(self, tnn, rfid):
        if not self.check_rfid_valid(rfid):
            return False
        return True

    def get_gcode_used_tnn(self):
        try:
            metadata = self.printer.lookup_object('gcode_metadata', None)
            if metadata is None:
                return None
            return metadata.get('gcode_used_tnn')
        except Exception:
            return None

    def check_printing_used_material(self, tnn):
        used_tnn = self.get_gcode_used_tnn()
        if used_tnn is None:
            return True
        return tnn in used_tnn

    def check_material_refill(self, tnn):
        logging.info('check_material_refill tnn: %s', tnn)

    def material_auto_refill(self, tnn):
        self.material_auto_refill_flag = True
        logging.info('material_auto_refill tnn: %s', tnn)

    def is_material_available(self, tnn):
        if tnn is None:
            return False
        return True

    def update_filament_pos(self, tnn, pos):
        logging.info('update_filament_pos tnn: %s, pos: %s', tnn, pos)

    def update_Tnn_map(self, tnn, content):
        if tnn is None:
            logging.warning('[error] tnn is None, last_tnn: %s, tnn: %s',
                           self.last_tnn, tnn)
            return
        self.box_state.Tnn_map[tnn] = content

    def update_same_material_list(self, same_material_list):
        self.box_state.update_same_material_list(same_material_list)

    def get_flush_temp(self, last_tnn, tnn):
        logging.info('flush_temp: %d', 0)
        return None

    def get_flush_max_temp(self, last_tnn, tnn):
        logging.info('flush_max_temp: %d', 0)
        return None

    def get_material_target_temp(self, tnn):
        try:
            db_path = 'creality/userdata/box/material_database.json'
            if os.path.exists(db_path):
                with open(db_path, 'r') as f:
                    db = json.load(f)
                logging.info('material database get nozzle temp: %s', db.get(tnn))
                return db.get(tnn, {}).get('nozzle_temp')
        except Exception:
            logging.warning('get material target temp fail')
        return None

    def get_material_target_max_temp(self, tnn):
        try:
            db_path = 'creality/userdata/box/material_database.json'
            if os.path.exists(db_path):
                with open(db_path, 'r') as f:
                    db = json.load(f)
                logging.info('material database get nozzle max temp: %s', db.get(tnn))
                return db.get(tnn, {}).get('nozzle_max_temp')
        except Exception:
            logging.warning('get material target max temp fail')
        return None

    def get_material_max_extrusion_speed(self, tnn):
        try:
            db_path = 'creality/userdata/box/material_database.json'
            if os.path.exists(db_path):
                with open(db_path, 'r') as f:
                    db = json.load(f)
                speed = db.get(tnn, {}).get('max_volumetric_speed')
                logging.info('get material extrusion speed: %d', speed or 0)
                return speed
        except Exception:
            logging.warning('get material extrusion speed fail')
        return None

    def get_flush_velocity(self, last_tnn, tnn):
        return None

    def get_flush_len(self, last_tnn, tnn):
        return None

    def cal_flush_list(self, tnn_list):
        return []

    def quickly_wait_heating(self, temp, timeout=60.):
        heater = self.printer.lookup_object('extruder').get_heater()
        eventtime = self.reactor.monotonic()
        while True:
            eventtime = self.reactor.pause(eventtime + 1.)
            cur_temp = heater.smoothed_temp
            if cur_temp >= temp:
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
            sensor = self.printer.lookup_object('filament_switch_sensor filament_sensor', None)
            if sensor is None:
                return None
            return sensor.runout_helper.filament_present
        except Exception:
            return None

    def get_five_way_sensor_detect(self):
        try:
            sensor = self.printer.lookup_object('filament_switch_sensor five_way_filament', None)
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
        self.gcode.run_script_from_command(
            'G0 X%.2f Y%.2f F12000' % (self.boxcfg.extrude_pos_x, self.boxcfg.extrude_pos_y))
        logging.info('self.extrude_pos_x: %s', self.boxcfg.extrude_pos_x)
        logging.info('self.extrude_pos_y: %s', self.boxcfg.extrude_pos_y)

    def move_to_cut(self):
        logging.info('self.boxcfg.cut_pos_x: %f', self.boxcfg.cut_pos_x)
        self.gcode.run_script_from_command(
            'G0 X%.2f Y%.2f F10000' % (self.boxcfg.cut_pos_x, self.boxcfg.cut_pos_y))

    def nozzle_clean(self):
        logging.info('self.clean_velocity: %s', self.boxcfg.clean_velocity)
        logging.info('self.clean_left_pos_x: %s', self.boxcfg.clean_left_pos_x)
        script = (
            'G0 X%.2f Y%.2f F%.2f\n'
            'G0 X%.2f Y%.2f F%.2f\n'
            'G0 X%.2f Y%.2f F%.2f\n'
            'M400'
        ) % (
            self.boxcfg.clean_left_pos_x, self.boxcfg.clean_left_pos_y, self.boxcfg.clean_velocity,
            self.boxcfg.clean_right_pos_x, self.boxcfg.clean_right_pos_y, self.boxcfg.clean_velocity,
            self.boxcfg.clean_left_pos_x, self.boxcfg.clean_left_pos_y, self.boxcfg.clean_velocity,
        )
        self.gcode.run_script_from_command(script)

    def z_move(self, z):
        self.gcode.run_script_from_command(
            'G91\n G0 F600\nG0 Z%.2f F600\nG90' % z)

    def z_down(self):
        self.z_move(-0.5)

    def z_restore(self):
        self.z_move(0.5)

    def cut_hall_find_zero(self):
        logging.info('[box] cut to return OK')

    def cut_hall_find_test(self):
        logging.info('[box] cut to return_3 OK')

    def cut_hall_test(self):
        logging.info('[box] cut sensor state test')
        return self.cut.state()

    def cut_hall_zero(self):
        logging.info('[box] cut sensor zero')

    def cut_material(self):
        logging.info('[box] cut to return failed' if not self.cut.state() else '[box] cut sensor detected')
        self.gcode.run_script_from_command(
            'G0 X%.2f Y%.2f F%.2f' % (self.boxcfg.cut_pos_x, self.boxcfg.cut_pos_y, self.boxcfg.cut_velocity))
        self.gcode.run_script_from_command('G2 I4 J0 P1 F10000')
        self.gcode.run_script_from_command('G3 I-4 J0 P1 F10000')

    def make_material_loose(self, tnn):
        self.gcode.run_script_from_command('G0 E-2 F600')

    def Tn_Extrude(self, tnn, length, velocity, temp):
        logging.info('extrude = %s', length)
        self.gcode.run_script_from_command('G0 E%.2f F%.2f' % (length, velocity))

    def extruder_extrude(self, length, velocity):
        self.gcode.run_script_from_command('G0 E%.2f F%.2f' % (length, velocity))

    def material_volume_to_length(self, volume, tnn=None):
        # Convert volumetric mm3 to linear mm
        try:
            db_path = 'creality/userdata/box/material_database.json'
            if os.path.exists(db_path):
                with open(db_path, 'r') as f:
                    db = json.load(f)
                coeff = db.get(tnn, {}).get('coefficient', 1.75)
            else:
                coeff = 1.75
            radius = coeff / 2.0
            length = volume / (math.pi * radius * radius)
            return length
        except Exception:
            return volume

    def get_flush_max_temp(self, last_tnn, tnn):
        return None

    def check_flush_temp_and_extrude(self, last_tnn, tnn, length):
        temp = self.get_flush_temp(last_tnn, tnn)
        if temp is not None:
            self.set_temp(temp)
            self.quickly_wait_heating(temp)
        self.extruder_extrude(length, 300.)

    def check_and_extrude(self, tnn, length, velocity):
        logging.info('check_and_extrude extrude: %s, velocity: %s', length, velocity)
        self.extruder_extrude(length, velocity)

    def check_speed_and_extrude(self, tnn, length, velocity):
        logging.info('check_speed_and_extrude')
        self.extruder_extrude(length, velocity)

    def extrude_process_stage7(self, tnn, addr):
        logging.info('extrude_process_stage7 tnn: %s', tnn)
        self.extrude_process_stage7_flag = True

    def extrude_process_auto_retry_process(self, tnn):
        logging.info('extrude_process_auto_retry_process')
        self.retry_index += 1

    def material_flush(self, last_tnn, tnn, flush_len):
        logging.info('flush; last_tnn: %s, current_tnn: %s', last_tnn, tnn)
        logging.info('flush_len: %s', flush_len)
        if flush_len and flush_len > 0:
            self.check_flush_temp_and_extrude(last_tnn, tnn, flush_len)

    def box_extrude_material(self, tnn, addr, length, velocity):
        logging.info('box_extrude_material tnn: %s, addr: %s', tnn, addr)
        cmd = (0x01 << 8) | (addr & 0xFF)
        self.send_data(addr, self.parse_data.parse_num_to_byte(cmd, 2))

    def box_extrude_material_part(self, tnn, addr, length, velocity):
        logging.info('box_extrude_material_part tnn: %s', tnn)

    def box_extrude_material_stage8(self, tnn, addr):
        logging.info('box_extrude_material_stage8')
        return 'stage8 return error'

    def box_retrude_material(self, tnn, addr, length, velocity):
        logging.info('box_retrude_material tnn: %s, addr: %s', tnn, addr)

    def box_retrude_material_filament_err_part(self, tnn, addr):
        logging.info('box_retrude_material_filament_err_part')

    def retrude_process_clear_flag(self):
        logging.info('retrude_process_clear_flag')

    def use_ending_material_flag_clear(self):
        self.is_use_ending_material = False
        logging.info('use_ending_material_flag_clear')

    def is_use_ending_material_flush(self, tnn):
        return self.is_use_ending_material

    def filament_err_tighten_up_event(self, tnn):
        logging.warning('[warning] tnn is None, error_tnn: %s', tnn)

    def filament_conflict_check(self, tnn):
        return False

    def power_loss_clean(self):
        logging.info('clean the data of power loss')

    def power_loss_restore(self, tnn):
        logging.info('power_loss_restore tnn: %s', tnn)

    def extrusion_all_materials(self, addrs):
        logging.info('extrude all material, last_cmd: %s', self.last_cmd)
        for addr in addrs:
            self.box_extrude_material(None, addr, 50, 300)

    def z_move(self, z):
        self.gcode.run_script_from_command(
            'G91\n G0 F600\nG0 Z%.2f F600\nG90' % z)

    def communication_test(self, addr):
        logging.info('%d. addr[%d] test start', self.timeout_times, addr)
        result = self.send_data(addr, b'\x00\x00\x01', timeout=TIMEOUT_SHORT_TIME)
        if result is not None:
            logging.info('%d. addr[%d] test finish', self.timeout_times, addr)
        return result

    def communication_create_connect(self, addr):
        return self.send_data(addr, b'\x00\x00\x02')

    def communication_extrude_process(self, addr, length, velocity, percent):
        logging.info('extrude = %s, velocity: %s, temp: %s, percent: %s, tnn: %s',
                    length, velocity, None, percent, None)
        return self.send_data(addr, b'\x00\x00\x03')

    def communication_retrude_process(self, addr, length, velocity):
        return self.send_data(addr, b'\x00\x00\x04')

    def communication_extrude2_process(self, addr, length, velocity, percent):
        return self.send_data(addr, b'\x00\x00\x05')

    def communication_get_box_state(self, addr):
        result = self.send_data(addr, b'\x00\x00\x10', timeout=TIMEOUT_SHORT_TIME)
        if result is None:
            logging.warning('communication_get_box_state return false, timeout_times: %d',
                           self.timeout_times)
        return result

    def communication_get_rfid(self, addr):
        return self.send_data(addr, b'\x00\x00\x11')

    def communication_get_remain_len(self, addr):
        return self.send_data(addr, b'\x00\x00\x12')

    def communication_get_hardware_status(self, addr):
        return self.send_data(addr, b'\x00\x00\x13')

    def communication_get_version_sn(self, addr):
        return self.send_data(addr, b'\x00\x00\x14')

    def communication_get_buffer_state(self, addr):
        return self.send_data(addr, b'\x00\x00\x15')

    def communication_get_filament_sensor_state(self, addr):
        return self.send_data(addr, b'\x00\x00\x16')

    def communication_set_box_mode(self, addr, mode):
        return self.send_data(addr, b'\x00\x00\x20')

    def communication_ctrl_connection_motor_action(self, addr, action):
        return self.send_data(addr, b'\x00\x00\x21')

    def communication_tighten_up_enable(self, addr, enable):
        return self.send_data(addr, b'\x00\x00\x22')

    def communication_set_pre_loading(self, addr, enable):
        return self.send_data(addr, b'\x00\x00\x23')

    def communication_measuring_wheel(self, addr):
        result = self.send_data(addr, b'\x00\x00\x24')
        if result:
            wheel = self.parse_data.get_measuring_wheel(result)
            logging.info('measuring_wheel = %d', wheel or 0)
        return result

    def generate_auto_get_rfid_func(self, addr):
        def function(eventtime):
            result = self.communication_get_rfid(addr)
            if result:
                rfid = self.parse_data.get_rfid(result)
                logging.info('tnn_rfid: %s', rfid)
            return self.reactor.monotonic() + 5.
        return function

    def check_and_extrude(self, tnn, length, velocity):
        logging.info('check_and_extrude extrude: %s, velocity: %s', length, velocity)
        self.extruder_extrude(length, velocity)

    def get_five_way_sensor_detect(self):
        try:
            sensor = self.printer.lookup_object('filament_switch_sensor five_way_filament', None)
            if sensor is None:
                return None
            return sensor.runout_helper.filament_present
        except Exception:
            return None


class MultiColorMeterialBoxWrapper:
    """Main Klipper extra class for the multi-color material box."""

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

        self.printer.register_event_handler('klippy:ready', self._handle_ready)

        # Register GCode commands
        gcode = self.gcode
        gcode.register_command('BOX_SEND_DATA', self.cmd_send_data)
        gcode.register_command('BOX_MODIFY_TN', self.cmd_modify_Tn_data)
        gcode.register_command('BOX_MODIFY_TN_INNER_DATA', self.cmd_modify_Tn_inner_data)
        gcode.register_command('BOX_MODIFY_TNN_MAP', self.cmd_modify_Tnn_map)
        gcode.register_command('BOX_CREATE_CONNECT', self.cmd_create_connect)
        gcode.register_command('BOX_GET_RFID', self.cmd_get_rfid)
        gcode.register_command('BOX_GET_REMAIN_LEN', self.cmd_get_remain_len)
        gcode.register_command('BOX_GET_BOX_STATE', self.cmd_get_box_state)
        gcode.register_command('BOX_GET_BUFFER_STATE', self.cmd_get_buffer_state)
        gcode.register_command('BOX_SET_BOX_MODE', self.cmd_set_box_mode)
        gcode.register_command('BOX_GET_FILAMENT_SENSOR_STATE', self.cmd_get_filament_sensor_state)
        gcode.register_command('BOX_CTRL_CONNECTION_MOTOR_ACTION', self.cmd_ctrl_connection_motor_action)
        gcode.register_command('BOX_RETRUDE_PROCESS', self.cmd_retrude_process)
        gcode.register_command('BOX_GET_HARDWARE_STATUS', self.cmd_get_hardware_status)
        gcode.register_command('BOX_GET_VERSION_SN', self.cmd_get_version_sn)
        gcode.register_command('BOX_EXTRUDE_PROCESS', self.cmd_extrude_process)
        gcode.register_command('BOX_EXTRUDE_2_PROCESS', self.cmd_extrude2_process)
        gcode.register_command('BOX_COMMUNICATION_TEST', self.cmd_communication_test)
        gcode.register_command('BOX_CUT_MATERIAL', self.cmd_cut_material)
        gcode.register_command('BOX_SET_TEMP', self.cmd_set_temp)
        gcode.register_command('BOX_SAVE_FAN', self.cmd_save_fan)
        gcode.register_command('BOX_RESTORE_FAN', self.cmd_restore_fan)
        gcode.register_command('BOX_MOVE_TO_CUT', self.cmd_move_to_cut)
        gcode.register_command('BOX_GO_TO_EXTRUDE_POS', self.cmd_go_to_extrude_pos)
        gcode.register_command('BOX_GET_FLUSH_LEN', self.cmd_get_flush_len)
        gcode.register_command('BOX_BLOW', self.cmd_blow)
        gcode.register_command('BOX_MOVE_TO_SAFE_POS', self.cmd_move_to_safe_pos)
        gcode.register_command('BOX_NOZZLE_CLEAN', self.cmd_nozzle_clean)
        gcode.register_command('BOX_TIGHTEN_UP_ENABLE', self.cmd_tighten_up_enable)
        gcode.register_command('BOX_MEASURING_WHEEL', self.cmd_measuring_wheel)
        gcode.register_command('BOX_SET_PRE_LOADING', self.cmd_set_pre_loading)
        gcode.register_command('BOX_EXTRUDE_MATERIAL', self.cmd_box_extrude_material)
        gcode.register_command('BOX_RETRUDE_MATERIAL', self.cmd_box_retrude_material)
        gcode.register_command('BOX_EXTRUDER_EXTRUDE', self.cmd_extruder_extrude)
        gcode.register_command('BOX_MATERIAL_FLUSH', self.cmd_material_flush)
        gcode.register_command('BOX_MATERIAL_CHANGE_FLUSH', self.cmd_material_change_flush)
        gcode.register_command('BOX_CUT_HALL_TEST', self.cmd_hall_test)
        gcode.register_command('BOX_CUT_HALL_ZERO', self.cmd_hall_zero)
        gcode.register_command('BOX_TN_EXTRUDE', self.cmd_Tn_Extrude)
        gcode.register_command('BOX_START_PRINT', self.cmd_box_start_print)
        gcode.register_command('BOX_END_PRINT', self.cmd_box_end_print)
        gcode.register_command('BOX_ENABLE_CFS_PRINT',
                               self.cmd_box_enable_CFS_print,
                               desc='BOX_ENABLE_CFS_PRINT ENABLE=%s')
        gcode.register_command('BOX_ERROR_CLEAR', self.cmd_error_clear)
        gcode.register_command('BOX_TNN_RETRY_PROCESS', self.cmd_Tnn_retry_process)
        gcode.register_command('BOX_CHECK_MATERIAL_REFILL', self.cmd_check_material_refill)
        gcode.register_command('BOX_SHOW_TNN_INNER_DATA', self.cmd_show_Tnn_data)
        gcode.register_command('BOX_GENERATE_FLUSH_ARRAY', self.cmd_generate_flush_array)
        gcode.register_command('BOX_RETRUDE_MATERIAL_WITH_TNN', self.cmd_retrude_material_with_tnn)
        gcode.register_command('BOX_ERROR_RESUME_PROCESS', self.cmd_error_resume_process)
        gcode.register_command('BOX_END', self.cmd_box_end)
        gcode.register_command('BOX_ENABLE_HEART_PROCESS', self.cmd_enable_heart_process)
        gcode.register_command('BOX_DISABLE_HEART_PROCESS', self.cmd_disable_heart_process)
        gcode.register_command('BOX_POWER_LOSS_RESTORE', self.cmd_power_loss_restore)
        gcode.register_command('BOX_EXTRUSION_ALL_MATERIALS', self.cmd_extrusion_all_materials)
        gcode.register_command('BOX_GET_FLUSH_VELOCITY_TEST', self.cmd_get_flush_velocity_test)
        gcode.register_command('BOX_SET_CURRENT_BOX_IDLE_MODE', self.cmd_BOX_SET_CURRENT_BOX_IDLE_MODE)
        gcode.register_command('BOX_UPDATE_SAME_MATERIAL_LIST', self.cmd_update_same_material_list)
        gcode.register_command('BOX_SHOW_FLUSH_LIST', self.cmd_show_flush_list)
        gcode.register_command('BOX_SHOW_ERROR', self.cmd_show_error)
        gcode.register_command('BOX_TEST_MAKE_ERROR', self.cmd_make_error)
        gcode.register_command('BOX_GET_GCODE_USED_TNN', self.cmd_get_gcode_used_tnn)
        gcode.register_command('BOX_ENABLE_AUTO_REFILL', self.cmd_set_enable_auto_refill)
        gcode.register_command('BOX_FIRST_POWER_ON_PRELOAD', self.cmd_first_power_on_preload)
        gcode.register_command('BOX_MODIFY_TN_DATA', self.cmd_modify_Tn_data)
        gcode.register_command('BOX_CUT_STATE', self.cmd_cut_state)

    def _handle_ready(self):
        self.box_action._handle_ready()
        self.box_save.find_objs()
        self.find_objs()

    def find_objs(self):
        self.toolhead = self.printer.lookup_object('toolhead')

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
        logging.info('gcode has no flush parameters')
        return None

    def get_status(self, eventtime=None):
        return {
            'current_tnn': self.current_tnn,
            'last_tnn': self.last_tnn,
            'error_list': self.error_list,
        }

    def heart_process(self, eventtime):
        if not self.box_action.heart_process_enable:
            return eventtime + 1.
        return eventtime + 5.

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

    def box_start_get_rfid_and_remain_len(self, addrs):
        for addr in addrs:
            rfid_data = self.box_action.communication_get_rfid(addr)
            if rfid_data:
                rfid = self.parse_data.get_rfid(rfid_data)
                logging.info('tnn_rfid: %s', rfid)

    def box_connect_state_check(self, addrs):
        for addr in addrs:
            state = self.get_connect_state(addr)
            if not state:
                logging.warning('addr[%s] is not connected', addr)

    def box_end(self):
        logging.info('box_end')
        self.box_action.disable_heart_process()

    def Tnn_retry_process(self, tnn):
        logging.info('Tnn_retry_process tnn: %s', tnn)
        self.box_action.retry_index = 0

    def Tn_action(self, tnn, addr, action):
        logging.info('Tn_action_flag is %s', action)

    def flush_material(self, last_tnn, tnn, flush_len):
        self.box_action.material_flush(last_tnn, tnn, flush_len)

    def material_change_flush(self, last_tnn, tnn):
        flush_len = self.get_flush_len(last_tnn, tnn)
        self.flush_material(last_tnn, tnn, flush_len)

    def generate_Tn_func(self, tnn):
        def function(gcmd):
            self.Tn_action(tnn, None, gcmd.get('ACTION', 'RUN'))
        return function

    def generate_Tnn_func(self, tnn):
        def function(gcmd):
            addr = gcmd.get_int('ADDRS', None)
            self.Tn_action(tnn, addr, gcmd.get('ACTION', 'RUN'))
        return function

    # ---- Error retry processes ----

    def flush_err_retry_process(self, tnn):
        logging.info('flush_err_retry_process')

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
        data_str = gcmd.get('DATA', '')
        logging.info('cmd_send_data addr=%d data=%s', addr, data_str)
        result = self.box_action.send_data(addr, bytes.fromhex(data_str.replace(' ', '')))
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
        if tnn and key:
            self.box_state.modify_Tn_inner_data(tnn, key, value)

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
        gcmd.respond_info('create_connect addr=%d result=%s' % (addr, result))

    def cmd_get_rfid(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        result = self.box_action.communication_get_rfid(addr)
        if result:
            rfid = self.parse_data.get_rfid(result)
            gcmd.respond_info('rfid: %s' % rfid)

    def cmd_get_remain_len(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        result = self.box_action.communication_get_remain_len(addr)
        if result:
            remain = self.parse_data.get_remain_len(result)
            gcmd.respond_info('remain_len: %s' % remain)

    def cmd_get_box_state(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        result = self.box_action.communication_get_box_state(addr)
        gcmd.respond_info('box_state: %s' % str(result))

    def cmd_get_buffer_state(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        result = self.box_action.communication_get_buffer_state(addr)
        if result:
            gcmd.respond_info('buffer_state: 0x%x' % (result[0] if result else 0))

    def cmd_set_box_mode(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        mode = gcmd.get('MODE', 'IDLE')
        self.box_action.communication_set_box_mode(addr, mode)

    def cmd_get_filament_sensor_state(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        result = self.box_action.communication_get_filament_sensor_state(addr)
        gcmd.respond_info('[box] filament sensor state: %x' % (result[0] if result else 0))

    def cmd_ctrl_connection_motor_action(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        action = gcmd.get('ACTION', 'OPEN')
        if action not in ('OPEN', 'CLOSE', 'RUN', 'TIGHT'):
            gcmd.respond_info("[warning] param error, ACTION only with 'OPEN' and 'CLOSE', 'RUN', 'TIGHT'")
            return
        self.box_action.communication_ctrl_connection_motor_action(addr, action)

    def cmd_retrude_process(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        length = gcmd.get_float('LENGTH', 100.)
        velocity = gcmd.get_float('VELOCITY', 300.)
        self.box_action.communication_retrude_process(addr, length, velocity)

    def cmd_get_hardware_status(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        result = self.box_action.communication_get_hardware_status(addr)
        gcmd.respond_info('hardware_status: %s' % str(result))

    def cmd_get_version_sn(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        result = self.box_action.communication_get_version_sn(addr)
        if result:
            gcmd.respond_info('version: %s, sn: %s' % ('unknown', 'unknown'))

    def cmd_extrude_process(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        length = gcmd.get_float('LENGTH', 100.)
        velocity = gcmd.get_float('VELOCITY', 300.)
        percent = gcmd.get_float('PERCENT', 100.)
        self.box_action.communication_extrude_process(addr, length, velocity, percent)

    def cmd_extrude2_process(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        length = gcmd.get_float('LENGTH', 100.)
        velocity = gcmd.get_float('VELOCITY', 300.)
        percent = gcmd.get_float('PERCENT', 100.)
        self.box_action.communication_extrude2_process(addr, length, velocity, percent)

    def cmd_communication_test(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        result = self.box_action.communication_test(addr)
        gcmd.respond_info('communication_test addr=%d result=%s' % (addr, result))

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
        flush_len = self.get_flush_len(last_tnn, tnn)
        gcmd.respond_info('flush_length: %s' % flush_len)

    def cmd_blow(self, gcmd):
        self.box_action.blow()

    def cmd_move_to_safe_pos(self, gcmd):
        self.box_action.move_to_safe_pos()

    def cmd_nozzle_clean(self, gcmd):
        self.box_action.nozzle_clean()

    def cmd_tighten_up_enable(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        enable = gcmd.get('ENABLE', 'ENABLE')
        if enable not in ('ENABLE', 'DISABLE'):
            gcmd.respond_info("param is error, ENABLE only with 'DISABLE' and 'ENABLE'")
            return
        self.box_action.communication_tighten_up_enable(addr, enable == 'ENABLE')

    def cmd_measuring_wheel(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        self.box_action.communication_measuring_wheel(addr)

    def cmd_set_pre_loading(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        enable = gcmd.get('ENABLE', 'ENABLE')
        self.box_action.communication_set_pre_loading(addr, enable == 'ENABLE')

    def cmd_box_extrude_material(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        length = gcmd.get_float('LENGTH', 100.)
        velocity = gcmd.get_float('VELOCITY', 300.)
        self.box_action.box_extrude_material(None, addr, length, velocity)

    def cmd_box_retrude_material(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        length = gcmd.get_float('LENGTH', 100.)
        velocity = gcmd.get_float('VELOCITY', 300.)
        self.box_action.box_retrude_material(None, addr, length, velocity)

    def cmd_extruder_extrude(self, gcmd):
        length = gcmd.get_float('LENGTH', 100.)
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
        tnn = gcmd.get('TNN', None)
        self.Tnn_retry_process(tnn)

    def cmd_check_material_refill(self, gcmd):
        tnn = gcmd.get('TNN', None)
        self.box_action.check_material_refill(tnn)

    def cmd_show_Tnn_data(self, gcmd):
        tnn = gcmd.get('TNN', None)
        data = self.box_state.get_Tnn_content(tnn)
        gcmd.respond_info('Tnn_content: %s' % str(data))

    def cmd_generate_flush_array(self, gcmd):
        logging.info('cmd_generate_flush_array')

    def cmd_retrude_material_with_tnn(self, gcmd):
        tnn = gcmd.get('TNN', None)
        addr = gcmd.get_int('ADDRS', 0)
        length = gcmd.get_float('LENGTH', 100.)
        velocity = gcmd.get_float('VELOCITY', 300.)
        self.box_action.box_retrude_material(tnn, addr, length, velocity)

    def cmd_error_resume_process(self, gcmd):
        tnn = gcmd.get('TNN', None)
        self.error_resume_process(tnn)

    def cmd_box_end(self, gcmd):
        self.box_end()

    def cmd_enable_heart_process(self, gcmd):
        self.box_action.enable_heart_process()

    def cmd_disable_heart_process(self, gcmd):
        self.box_action.disable_heart_process()

    def cmd_power_loss_restore(self, gcmd):
        tnn = gcmd.get('TNN', None)
        power_on = gcmd.get('POWER_ON', None)
        if power_on not in ('ENABLE', 'DISABLE', None):
            gcmd.respond_info("[warning] the param of 'POWER_ON' is error, only 'ENABLE' and 'DISABLE'")
            return
        self.box_action.power_loss_restore(tnn)

    def cmd_extrusion_all_materials(self, gcmd):
        addrs_str = gcmd.get('ADDRS', '0')
        addrs = [int(a) for a in addrs_str.split(',') if a.strip().isdigit()]
        self.box_action.extrusion_all_materials(addrs)

    def cmd_get_flush_velocity_test(self, gcmd):
        last_tnn = gcmd.get('LAST_TNN', None)
        tnn = gcmd.get('TNN', None)
        velocity = self.box_action.get_flush_velocity(last_tnn, tnn)
        gcmd.respond_info('flush_velocity: %s' % velocity)

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
        tnn = self.box_action.get_gcode_used_tnn()
        gcmd.respond_info('gcode_used_tnn: %s' % tnn)

    def cmd_set_enable_auto_refill(self, gcmd):
        enable = gcmd.get('ENABLE', 'ENABLE')
        if enable == 'ENABLE':
            logging.info('enable material automatic refill')
        else:
            logging.info('disable material automatic refill')

    def cmd_first_power_on_preload(self, gcmd):
        addr = gcmd.get_int('ADDRS', 0)
        self.gcode.run_script_from_command('BOX_FIRST_POWER_ON_PRELOAD ADDRS=%d' % addr)

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
