import shodan
import os
from dotenv import load_dotenv, find_dotenv

def validate_input(name: str, val:str, query:str, add_space:bool) -> str:
    if val is not None:
        query = query + f"{name}:{val}"
        if add_space is True:
            query = query + " "
    return query
def make_query(product: str, port: str, os_in: str, country: str) -> str:
    query = ""
    query = validate_input('product', product, query, True)
    query = validate_input('port', port, query, True)
    query = validate_input('os', os_in, query, True)
    query = validate_input('country', country, query, False)
    if query == "":
        print(f"ERROR: Query is Empty. Please fill some fields")
    return query
def make_connection():
    load_dotenv(find_dotenv())
    SHDN_API_KEY = os.getenv("SHODAN_API_KEY")
    connection = shodan.Shodan(SHDN_API_KEY)
    return connection
def exposure_scan(input_dict):
    pdt = input_dict['product']
    prt = input_dict['port']
    os_dev = input_dict['os']
    cntry = input_dict['country']
    query = make_query(pdt, prt, os_dev, cntry)
    connection = make_connection()
    search_result = connection.search(query)
    print(f"{search_result['total']}")
    return search_result