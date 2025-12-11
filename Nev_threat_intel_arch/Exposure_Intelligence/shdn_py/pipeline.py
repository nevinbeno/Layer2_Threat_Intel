from fetch_data import get_data_from_user
from scan import exposure_scan
from save_to_json import save_as_json
from save_as_map import generate_map

if __name__ == '__main__':
    input_dict = get_data_from_user()
    search_result = exposure_scan(input_dict)
    file_path_then_name_list = save_as_json(search_result, input_dict)
    success = generate_map(file_path_then_name_list[0], file_path_then_name_list[1])
    if success is True:
        print("done")