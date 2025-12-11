import os
import json

def validate_input(val:str, name:str, add_dash:bool) -> str:
    if val is not None:
        name = name + f"{val}"
        if add_dash is True:
            name = name + "_"
    return name

def make_filename(input_dict):
    pdt = input_dict['product']
    prt = input_dict['port']
    os_dev = input_dict['os']
    cntry = input_dict['country']
    file_name = ""
    file_name = validate_input(pdt, file_name, True)
    file_name = validate_input(prt, file_name, True)
    file_name = validate_input(os_dev, file_name, True)
    file_name = validate_input(cntry, file_name, False)
    file_name = file_name + ".json"
    return file_name

def save_as_json(result, input_dict):
    status = False
    pwd = os.path.dirname(os.path.abspath(__file__))
    shdn_folder_path = os.path.join(pwd, "..", "shdn_json")
    os.makedirs(shdn_folder_path, exist_ok=True)
    file_name = make_filename(input_dict)
    file_path = os.path.join(shdn_folder_path, file_name)

    with open (file_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=4)
        print(f"Threat Intelligence Update: scan result saved as a json file; File name = {file_name}")
        status = True
    if status is False:
        print(f"ERROR: Failed to generate the json file. ")
        #  exit()
    return [file_path, file_name]