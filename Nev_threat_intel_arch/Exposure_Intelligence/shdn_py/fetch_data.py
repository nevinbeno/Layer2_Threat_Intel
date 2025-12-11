def get_data_from_user():
    print(f"Enter the data: ")
    product = input(f"Enter the product: ")
    port = input(f"Enter a valid port number: ")
    os = input(f"Enter the OS running on the device: ")
    cntry = input(f"Enter the country: ")
    input_data_dict = {'product':product, 'port':port, 'os':os, 'country':cntry}
    print(f"Threat Intellgence Update: Data fetched. ")
    return input_data_dict