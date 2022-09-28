import re
from email_validator import validate_email, EmailNotValidError
from functools import partial

import requests
from kivy.properties import StringProperty, ColorProperty
from kivy.uix.boxlayout import BoxLayout
from kivymd.app import MDApp
from kivy.uix.screenmanager import ScreenManager
from kivy.lang.builder import Builder
from kivy.core.window import Window
import hashlib
import sqlite3
import datetime

from kivymd.uix.button import MDFlatButton
from kivymd.uix.card import MDCard
from kivymd.uix.dialog import MDDialog
from kivymd.uix.list import OneLineAvatarListItem
from kivymd.uix.snackbar import Snackbar

Window.size = (400, 700)
# Loading the kivy components
Builder.load_file('news_item.kv')
Builder.load_file("crypto_coin_item.kv")
Builder.load_file("coin_holdings.kv")

kv = """
<Content>
    orientation: "vertical"
    spacing: "12dp"
    size_hint_y: None
    height: "120dp"

    MDLabel:
        id:add_coin_amt_text
        text:
        font_size:20
        halign:'left'
    MDTextField:
        id:amount_text
        hint_text:"Enter amount:"
        hint_text_color:1,0,0,1
        text_color:1,0,0,1

<Item>
    text:root.text
    on_press:app.press_handler(root.text)
    ImageLeftWidget:
        source: root.source
"""


Builder.load_string(kv)


def is_email_formated_correctly(email):
    try:
        validate_email(email)
        return True
    except EmailNotValidError:
        return False


def is_strong_password(password):
    return (
        len(password) >= 8 and
        re.search(r"\d", password) and
        re.search(r"[A-Z]", password)
    )


class Content(BoxLayout):
    pass


class Item(OneLineAvatarListItem):
    text = StringProperty()
    source = StringProperty()


def calc_t_delta(t_delta):
    """function to convert tht login time stamp into
    seconds for comparison to get the last logged in user"""
    # Returns time stamp time as seconds (Integer)
    time_delta = datetime.datetime.now() - datetime.datetime.fromtimestamp(int(t_delta))
    return time_delta.total_seconds()


class coin_holdings(MDCard):
    """Class Implementation for portfolio to add coins to it"""
    id = StringProperty()
    icon = StringProperty()
    coin_name = StringProperty()
    price = StringProperty()
    holdings = StringProperty()


class crypto_coin_item(MDCard):
    """ Class implementation of crypto coin base"""
    id = StringProperty()
    icon = StringProperty()
    coin_name = StringProperty()
    price = StringProperty()
    change = StringProperty()
    color = ColorProperty()
    pass


class news_item(MDCard):
    """Class implementation of news item """
    # Inherits: MDCard
    # This class creates the news item
    news_text = StringProperty()
    news_url = StringProperty()
    pass


class cryptoUpdates(MDApp):
    """Contains methods for the functions of the app"""

    # ------- Theme settings-------- #
    primary_color = "#191e29"
    accent_color = "#01c38d"
    secondary_text_color = "#696e79"
    primary_text_color = "#ffffff"
    secondary_background = "#2F343E"
    # ------------------------------#

    remember_me = None
    # dialog = popup containing the coins
    dialog = None
    # details_dialog = popup  to add coins to the portfolio
    details_dialog = None
    # portfolio data variable
    portfolio = 0

    # Default Coin and update time
    update_time = "24h"
    currency = "USD"

    def build(self):

        self.theme_cls.theme_style = "Dark"
        self.theme_cls.primary_palette = "Green"
        ############################################################################################
        self.screenmanager = ScreenManager()
        self.screenmanager.add_widget(Builder.load_file("welcome.kv"))
        self.screenmanager.add_widget(Builder.load_file("login.kv"))
        self.screenmanager.add_widget(Builder.load_file("sign_up.kv"))
        self.screenmanager.add_widget(Builder.load_file("main.kv"))
        ###########################################################################################
        # ----------- Initializing database ----------- #
        self.connection = sqlite3.connect('Users.db')
        self.cursor = self.connection.cursor()
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS Users
                      (email TEXT UNIQUE, password VARBINARY, time_stamp INTEGER, remember_me INTEGER)''')
        # -------------------------------------------- #
        return self.screenmanager

    def on_start(self):
        """ Built in function starts when the app starts"""
        self.auto_login()
        self.build_news_list()
        self.build_coin_list()

    def change_screen(self, screen):
        """Contains statements to change screens and screen transitions"""
        # Arguments : screen
        # Type: text/string
        # accepts the name of the screen
        self.screenmanager.current = screen
    # ################ USER LOGIN REGISTRATION #####################################################

    def auto_login(self):
        """Auto Login for the application to login user automatically
        without requiring user to enter credentials"""
        # Arguments: None
        # return : None
        self.cursor.execute("select email, time_stamp from users where remember_me = 1")
        data = self.cursor.fetchall()
        # maintains a list if more than one user enabled remember me
        t_delta = []
        if len(data) == 0:
            print("Please login")
        else:
            for item in data:
                t_delta.append(calc_t_delta(item[1]))
            # -----------------------------------------#
            # Logging in the user #
            selected_row = t_delta.index(min(t_delta))
            currentUser = data[selected_row][0]
            print("Current User:", currentUser)
            # self.screenmanager.get_screen("main").ids.username.text = currentUser
            time_stamp = datetime.datetime.now().timestamp()
            update_time_stamp = (time_stamp, currentUser)
            # time_stamp need to be updated in case of login to make sure
            # that the last logged in user is the recent.
            self.cursor.execute(f"update users set time_stamp=? where email=?", update_time_stamp)
            self.connection.commit()
            print("Login Successful")
            self.change_screen("main")

    def logout_user(self):
        """function to log out user when needed
        Sets the remember me status for all user false
        causing them to log in again to use the app"""
        set_logout = (0,)
        self.cursor.execute(f"update users set remember_me=? ", set_logout)
        self.connection.commit()
        # change the screen so after logout the user cannot access any functions of the app
        self.change_screen("welcome")

    def login_user(self, email, pwd):
        """Contains statements for loging in the User """
        # Uses Sqlite Database to authenticate the user
        # Arguments: email (string), pwd (string)
        # returns : None
        user_email = email
        currentPass = pwd
        # converting to hash to check if the password is same or not
        currentHash = hashlib.sha256(currentPass.encode()).hexdigest()
        # -------------------------------------------
        t = (user_email,)
        # Create time stamp
        time_stamp = datetime.datetime.now().timestamp()

        update_time_stamp = (time_stamp, self.remember_me, user_email)
        self.cursor.execute(f"update users set time_stamp=?, remember_me=? where email=?", update_time_stamp)
        self.connection.commit()
        self.cursor.execute('SELECT email,password, time_stamp FROM users WHERE email=?', t)
        row = self.cursor.fetchone()
        if row is None:
            print("Account not found")
            Snackbar(
                text="No Accounts Found! Try Sign Up",
                snackbar_x="10dp",
                snackbar_y="10dp",
            ).open()
        else:
            fetchedHash = row[1]
            if fetchedHash == currentHash:
                print("Login Success.")
                self.change_screen("main")
                # self.screenmanager.get_screen("main").ids.username.text = user_email
            else:
                print("Login Fail.")
                Snackbar(
                    text="Login Failed, email/password is incorrect",
                    snackbar_x="10dp",
                    snackbar_y="10dp",
                ).open()

    def handle_remember_me(self, state):
        """function to set state of remember me"""
        if state == 'down':
            self.remember_me = True
        else:
            self.remember_me = False

    def register_user(self, email, pwd, confirm_pwd):
        """Contains Statements to register new user"""
        if is_email_formated_correctly(email):
            if is_strong_password(pwd):

                if pwd == confirm_pwd:
                    currentUser = email
                    txtPassword = pwd
                    # converting the password to hash to store in DB for security
                    currentPassword = hashlib.sha256(txtPassword.encode()).hexdigest()
                    time_stamp = datetime.datetime.now().timestamp()
                    self.cursor.execute("insert into users values (?, ?, ?,?)", (currentUser, currentPassword, time_stamp, 0))
                    self.connection.commit()
                    # opens a snackbar if registration is successful
                    Snackbar(
                        text="Register successful!",
                        snackbar_x="10dp",
                        snackbar_y="10dp",
                    ).open()
                #     ------------------------------------   #
                else:
                    # opens a snackbar if registration is failed by incorrect password
                    Snackbar(
                        text="Passwords doesn't match, Please Try again",
                        snackbar_x="10dp",
                        snackbar_y="10dp",
                    ).open()
            else:
                Snackbar(
                    text="Please select a strong password",
                    snackbar_x="10dp",
                    snackbar_y="10dp",
                ).open()
        else:
            Snackbar(
                text="Please enter a valid Email",
                snackbar_x="10dp",
                snackbar_y="10dp",
            ).open()
# ################# USER LOGIN AND REGISTRATION ###############################################################
# ############ CRYPTO NEWS, COIN DATA AND PORTFOLIO ###########################################################

    def build_news_list(self):
        response = requests.get(
            "https://cryptopanic.com/api/v1/posts/?auth_token=9c8754d8d24840b109cc26108d883dce8eab8b50&public=true")

        data = response.json()
        for item in data['results']:
            self.news_item = news_item()
            self.news_item.news_url = item["url"]
            self.news_item.news_text = item["title"]
            self.screenmanager.get_screen("main").ids.news_content.add_widget(self.news_item)

    def build_coin_list(self):
        url = f"https://api.coingecko.com/api/v3/coins/markets?vs_currency={self.currency}&order=market_cap_desc&per_page=50&page=1&sparkline=false&price_change_percentage={self.update_time}"
        response = requests.get(url)
        self.coin_data = response.json()
        for item in self.coin_data:
            self.crypto_coin_item = crypto_coin_item()
            self.crypto_coin_item.id = str(item['market_cap_rank'])
            self.crypto_coin_item.coin_name = item['name']
            self.crypto_coin_item.icon = item['image']
            self.crypto_coin_item.price = "{:.2f}".format(item['current_price'])
            if item['price_change_percentage_24h'] >= 0:
                self.crypto_coin_item.color = [77/255, 167/255, 38/255, 1]
            else:
                self.crypto_coin_item.color = [204/255, 0, 0, 1]
            self.crypto_coin_item.change = "{:.2f}%".format(item['price_change_percentage_24h'])
            self.screenmanager.get_screen("main").ids.coin_layout.add_widget(self.crypto_coin_item)
# #############################################################################################################
    # --------------- Settings ---------------------------------- #

    def reload_coin_base(self):
        print(self.currency)
        print(self.update_time)
        self.screenmanager.get_screen("main").ids.coin_layout.clear_widgets()
        self.build_coin_list()

    def handle_currency_change(self, currency):
        self.currency = currency
        print(self.currency)
        self.reload_coin_base()

    def handle_Update_time(self, update_time):
        self.update_time = update_time
        print(self.update_time)
        self.screenmanager.get_screen("main").ids.update_time_text.text = self.update_time
        self.reload_coin_base()
    # ----------------------------------------------------------- #
# ############ CRYPTO NEWS, COIN DATA AND PORTFOLIO ###########################################################

# -------------- PORTFOLIO ---------------------------------------------------------- #
    def build_coin_holding_list(self, coin, *args):
        """method to construct the coin container for the portfolio"""
        self.details_dialog.dismiss()
        # ------------------------------------
        requested_coin = None
        for i in self.coin_data:
            if i['name'] == coin:
                requested_coin = i
        # ------------------------------------
        # Updating the UI elements
        # do not touch this unless you know what are you doing
        self.coin_holdings = coin_holdings()
        self.coin_holdings.coin_name = requested_coin['symbol']
        self.coin_holdings.icon = requested_coin['image']
        self.coin_holdings.id = str(requested_coin['market_cap_rank'])
        self.coin_holdings.price = "{:.2f}".format(requested_coin['current_price'])
        self.portfolio += requested_coin['current_price'] * float(self.details_dialog.content_cls.ids.amount_text.text)
        self.coin_holdings.holdings = str(self.details_dialog.content_cls.ids.amount_text.text)
        self.screenmanager.get_screen("main").ids.portfolio_layout.add_widget(self.coin_holdings)
        self.screenmanager.get_screen("main").ids.net_holdings.text = "${:.3f}".format(self.portfolio)
        self.details_dialog.content_cls.ids.amount_text.text = ""
        self.details_dialog.content_cls.ids.add_coin_amt_text.text = ""
        self.details_dialog = None
        self.dialog = None
# -------------------------------------------------------------------------------------------------- #

    def create_items(self):
        """method to construct the crypto coin list
           This list is used to display the coins in the dialog"""
        self.coin=[]
        for item in self.coin_data:
            self.item = Item()
            self.item.text = item['name']
            self.item.source = item['image']
            self.coin.append(self.item)
###############################################################################################

    def show_confirmation_dialog(self):
        if not self.dialog:
            self.create_items()
            # initializing the dialog box for displaying the coins
            #  Warning: do not modify this
            self.dialog = MDDialog(
                title="Add Bitcoin",
                type="confirmation",
                items=self.coin,
                buttons=[
                    MDFlatButton(
                        text="CANCEL",
                        theme_text_color="Custom",
                        text_color=self.theme_cls.primary_color,
                        on_press=self.close_dialog,
                    ),
                ],
            )
            # ------------------------------------------------------
        self.dialog.open()
#######################################################################################################

    def press_handler(self, *args):
        """method to handle the amount adding functions for the portfolio"""
        self.dialog.dismiss()
        buttoncallback = partial(self.build_coin_holding_list, args[0])
        if not self.details_dialog:
            #  initializing the dialog box for adding the amount of coins
            #  Warning: do not modify this
            self.details_dialog = MDDialog(
                title="Add Coin Amount",
                type="custom",
                content_cls=Content(),
                buttons=[
                    MDFlatButton(
                        text="CANCEL",
                        theme_text_color="Custom",
                        text_color=self.theme_cls.primary_color,
                        on_press=self.close_dialog,
                    ),
                    MDFlatButton(
                        text="ADD",
                        theme_text_color="Custom",
                        text_color=self.theme_cls.primary_color,
                        on_press=buttoncallback
                    ),
                ],
            )
            # ----------------------------------------------------------------
            # displaying the coin name so the user can enter the correct amount
            self.details_dialog.content_cls.ids.add_coin_amt_text.text = args[0]
        self.details_dialog.open()
##################################################################################################
##################################################################################################

    def close_dialog(self, args):
        """ method for dismissing the dialog boxes when needed"""
        self.dialog.dismiss()
        self.dialog = None

        if self.details_dialog:
            self.details_dialog.dismiss()
            self.details_dialog = None
####################################################################################################


cryptoUpdates().run()
