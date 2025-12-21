# Shodan API setup
- Visit [NVD api requests page](https://nvd.nist.gov/developers/request-an-api-key), create an account (provide your organization name and type, and your email adderess)/ login using your account. 
    >🚨 Official email id's are preferred for better user experience and API 
- You will receive an email containing some `UUIDs`, then navigate to the page recommended, to verify your API KEY with your registered email and the `UUID` you've received. 
    > ⚠️ Never expose that API key. 
- Store that inside `.env` file, 
    ```env
    NVD_API_key = (paste your code)
    ```
______
[Click Here to go back to the README file](../README.md)