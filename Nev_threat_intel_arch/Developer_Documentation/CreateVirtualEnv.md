# Step 1: $Create$ $a$ $Virtual$ $Environment$
### Steps: 
1. Create a folder, get into it in VS Code. 
2. You see in terminal, like, 
    ```bash
    > # windows
    ```
    or
    ```bash
    $ # linux
    ```
    _____
3. Create a Virtual Environment. 
    ```bash
    $ python -m venv venv # windows and linux
    ```
    This creates a folder named *Venv*
    ```
    CRATIP/
    └── venv/
    ```
    This is the **Isolated Python Virtual Environment**. 
____
4. Activate the virtual environment
Run this in the terminal of VS Code
    ```bash
    > venv\Scripts\activate # windows only
    ```
    ```bash
    $ source venv/bin/activate # Linux only
    ```
    You will see the change in the terminal: 

    ```bash
    (venv) > # windows
    ```
    ```bash
    (venv) $ # linux
    ```
    Means, it is ready !!!
____
#### If you want to DEACTIVATE the (venv), just run 
```bash
(venv)$ deactivate # (windows and linux)
```
**Output**: 
```bash
$
```
______
[Click Here to go back to the README file](README.md)