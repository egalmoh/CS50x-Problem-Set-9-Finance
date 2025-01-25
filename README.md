# CS50x Problem Set 9: Finance


### Overview
This project is part of the CS50x course and implements a stock trading simulation platform. Users can register, log in, and manage a virtual portfolio by buying and selling stocks using real-time stock data.


### Features
- **User Authentication:** Secure registration and login system.
- **Buy and Sell Stocks:** Users can trade stocks based on current market prices.
- **Portfolio Management:** View current holdings, track profits/losses, and monitor account balance.
- **Transaction History:** Comprehensive log of all stock transactions.
- **Real-Time Stock Data:** Fetches live stock prices using the IEX Cloud API.


### Technologies Used
- **Flask:** Backend framework for building the application.
- **SQLite:** Database for storing user data and transaction history.
- **HTML/CSS/JavaScript:** Frontend for creating the user interface.
- **IEX Cloud API:** Used to fetch real-time stock data.


### Installation
1. Clone the repository:
    ```
    git clone https://github.com/egalmoh/CS50x-Problem-Set-9-Finance.git
    cd CS50x-Problem-Set-9-Finance
    ```

2. Set up a virtual environment and install dependencies:
    ```
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

3. Configure the IEX Cloud API key:
    - Sign up for an IEX Cloud account.
    - Get your API key.
    - Create a .env file in the project directory and add the following line:
        ```
        API_KEY=your_iex_cloud_api_key
        ```
4. Initialize the database:
    ```
    flask db upgrade
    ```
5. Run the application:
    ```
    flask run
    ```


### Usage
1. Open the application in your web browser at http://127.0.0.1:5000/.
2. Register for a new account or log in if you already have one.
3. Start trading by searching for stocks, buying/selling shares, and managing your portfolio.


### License
This project is licensed under the MIT License. See the LICENSE file for details.


### Acknowledgments
This project is inspired by the CS50x Problem Set 9 and uses the IEX Cloud API for stock data.