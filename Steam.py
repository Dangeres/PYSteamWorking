import time
import json
import hmac
import base64
from python_anticaptcha import AnticaptchaClient, ImageToTextTask
import pickle
import hashlib
import requests
import urllib
import re
from random import uniform
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

from bs4 import BeautifulSoup

THINGS_TRY = 10
bot_session_folder = 'bot_session'


import enum
from typing import List
import struct
import copy

class Confirmation:
    def __init__(self, _id, data_confid, data_key):
        self.id = _id.split('conf')[1]
        self.data_confid = data_confid
        self.data_key = data_key


class Tag(enum.Enum):
    CONF = 'conf'
    DETAILS = 'details'
    ALLOW = 'allow'
    CANCEL = 'cancel'


class ConfirmationExecutor:
    CONF_URL = "https://steamcommunity.com/mobileconf"

    def __init__(self, identity_secret: str, my_steam_id: str, session: requests.Session) -> None:
        self._my_steam_id = my_steam_id
        self._identity_secret = identity_secret
        self._session = session

    def generate_confirmation_key(self, identity_secret: str, tag: str, timestamp: int = int(time.time())) -> bytes:
        buffer = struct.pack('>Q', timestamp) + tag.encode('ascii')
        return base64.b64encode(hmac.new(base64.b64decode(identity_secret), buffer, digestmod=hashlib.sha1).digest())


    # It works, however it's different that one generated from mobile app
    def generate_device_id(self, steam_id: str) -> str:
        hexed_steam_id = hashlib.sha1(steam_id.encode('ascii')).hexdigest()
        return 'android:' + '-'.join([hexed_steam_id[:8],
                                    hexed_steam_id[8:12],
                                    hexed_steam_id[12:16],
                                    hexed_steam_id[16:20],
                                    hexed_steam_id[20:32]])


    def send_trade_allow_request(self, trade_offer_id: str) -> dict:
        confirmations = self._get_confirmations()
        confirmation = self._select_trade_offer_confirmation(confirmations, trade_offer_id)
        return self._send_confirmation(confirmation)

    def confirm_sell_listing(self, asset_id: str) -> dict:
        confirmations = self._get_confirmations()
        confirmation = self._select_sell_listing_confirmation(confirmations, asset_id)
        return self._send_confirmation(confirmation)

    def _send_confirmation(self, confirmation: Confirmation) -> dict:
        tag = Tag.ALLOW
        params = self._create_confirmation_params(tag.value)
        params['op'] = tag.value,
        params['cid'] = confirmation.data_confid
        params['ck'] = confirmation.data_key
        headers = {'X-Requested-With': 'XMLHttpRequest'}
        return self._session.get(self.CONF_URL + '/ajaxop', params=params, headers=headers).json()

    def _get_confirmations(self) -> List[Confirmation]:
        confirmations = []
        confirmations_page = self._fetch_confirmations_page()
        soup = BeautifulSoup(confirmations_page.text, 'html.parser')
        if soup.select('#mobileconf_empty'):
            return confirmations
        for confirmation_div in soup.select('#mobileconf_list .mobileconf_list_entry'):
            _id = confirmation_div['id']
            data_confid = confirmation_div['data-confid']
            data_key = confirmation_div['data-key']
            confirmations.append(Confirmation(_id, data_confid, data_key))
        return confirmations

    def _fetch_confirmations_page(self) -> requests.Response:
        tag = Tag.CONF.value
        params = self._create_confirmation_params(tag)
        headers = {'X-Requested-With': 'com.valvesoftware.android.steam.community'}
        response = self._session.get(self.CONF_URL + '/conf', params=params, headers=headers)
        if 'Steam Guard Mobile Authenticator is providing incorrect Steam Guard codes.' in response.text:
            return None
        return response

    def _fetch_confirmation_details_page(self, confirmation: Confirmation) -> str:
        tag = 'details' + confirmation.id
        params = self._create_confirmation_params(tag)
        response = self._session.get(self.CONF_URL + '/details/' + confirmation.id, params=params)
        return response.json()['html']

    def _create_confirmation_params(self, tag_string: str) -> dict:
        timestamp = int(time.time())
        confirmation_key = self.generate_confirmation_key(self._identity_secret, tag_string, timestamp)
        android_id = self.generate_device_id(self._my_steam_id)
        return {'p': android_id,
                'a': self._my_steam_id,
                'k': confirmation_key,
                't': timestamp,
                'm': 'android',
                'tag': tag_string}

    def _select_trade_offer_confirmation(self, confirmations: List[Confirmation], trade_offer_id: str) -> Confirmation:
        for confirmation in confirmations:
            confirmation_details_page = self._fetch_confirmation_details_page(confirmation)
            confirmation_id = self._get_confirmation_trade_offer_id(confirmation_details_page)
            if confirmation_id == trade_offer_id:
                return confirmation
        return None

    def _select_sell_listing_confirmation(self, confirmations: List[Confirmation], asset_id: str) -> Confirmation:
        for confirmation in confirmations:
            confirmation_details_page = self._fetch_confirmation_details_page(confirmation)
            confirmation_id = self._get_confirmation_sell_listing_id(confirmation_details_page)
            if confirmation_id == asset_id:
                return confirmation
        return None

    @staticmethod
    def _get_confirmation_sell_listing_id(confirmation_details_page: str) -> str:
        soup = BeautifulSoup(confirmation_details_page, 'html.parser')
        scr_raw = soup.select("script")[2].text.strip()
        scr_raw = scr_raw[scr_raw.index("'confiteminfo', ") + 16:]
        scr_raw = scr_raw[:scr_raw.index(", UserYou")].replace("\n", "")
        return json.loads(scr_raw)["id"]

    @staticmethod
    def _get_confirmation_trade_offer_id(confirmation_details_page: str) -> str:
        soup = BeautifulSoup(confirmation_details_page, 'html.parser')
        full_offer_id = soup.select('.tradeoffer')[0]['id']
        return full_offer_id.split('_')[1]


class Steam:
    def __init__(self, login, password, secret, ident, need_login = True):
        self.login = login
        self.password = password
        self.secret = secret
        self.captcha_gid = -1
        self.captcha_answer = ''
        self.__session = None
        self.steam_id = None
        self.session_id = None
        self.ident = ident

        if need_login:
            self.__session = self.__get_steam_session()

    def solve_captcha(self):
        key = '15a71ba0b04ff7b6e1e60504c24c8f30'

        client = AnticaptchaClient(key)
        task = ImageToTextTask(urllib.request.urlopen('https://steamcommunity.com/public/captcha.php?gid=' + self.captcha_gid))
        
        job = client.createTask(task)
        job.join()
        
        try:
            self.captcha_answer = job.get_captcha_text()
        except Exception as e:
            print('Problem with captcha')
            print(e)

        return self.captcha_answer
    
    def get_auth_code(self):
        def bytes_to_int(bytes):
            result = 0
            for b in bytes:
                result = result * 256 + int(b)
    
            return result
    
        t = int(time.time() / 30)
        key = base64.b64decode(self.secret)
        t = t.to_bytes(8, 'big')
        digester = hmac.new(key, t, hashlib.sha1)
        signature = digester.digest()
        signature = list(signature)
        start = signature[19] & 0xf
        fc32 = bytes_to_int(signature[start:start+4])
        fc32 &= 2147483647
        fullcode = list('23456789BCDFGHJKMNPQRTVWXY')
        length = len(fullcode)
        code = ''

        for i in range(5):
            code += fullcode[fc32%length]
            fc32 //= length
    
        return code

    def __get_notify_data(self, session = None):
        result = {'isLogin': False, 'steamid': None, 'sessionid': None, 'tradeOffers': False}

        if session is None:
            session = self.__session

        if session is None:
            return result

        try:
            response = json.loads(session.get('https://steamcommunity.com/actions/GetNotificationCounts').text)

            print("Auth check request is %s" % str(response))

            if response is not None:
                result['isLogin'] = True

                steam_cookie_values = session.cookies.get_dict()

                if steam_cookie_values.get('steamLoginSecure'):
                    result['steamid'] = steam_cookie_values['steamLoginSecure'].split('%7C%7C')[0]
                elif steam_cookie_values.get('steamRememberLogin'):
                    result['steamid'] = steam_cookie_values['steamRememberLogin'].split('%7C%7C')[0]

                self.steam_id = result['steamid']

                result['sessionid'] = steam_cookie_values.get('sessionid')
                self.session_id = result['sessionid']

                if response['notifications'].get('1') is not None and response['notifications'].get('1') > 0:
                    result['tradeOffers'] = True
                
            else:
                result['isLogin'] = False

        except Exception as e:
            pass

        return result

    def isLogin(self):
        return self.__get_notify_data().get('isLogin', False)

    def get_uid(self):
        return self.steam_id

    def get_session_id(self):
        return self.session_id

    def hasIncomeOffers(self):
        return self.__get_notify_data().get('tradeOffers', False)

    def get_offers(self):
        result = []

        if self.hasIncomeOffers():
            web_page = self.__session.get('https://steamcommunity.com/profiles/%s/tradeoffers/' % self.get_uid())

            soup = BeautifulSoup(web_page.text, 'html.parser')
                
            offers_raw = soup.find_all('div', attrs= {'class': 'tradeoffer'})

            for offer_raw in offers_raw:
                sender = offer_raw.find('a', attrs={'class': "btn_grey_grey btn_medium ico_hover btn_report"})
                sender_id = None

                if sender:
                    sender_id = re.search("\'(\d+)\'", sender['onclick']).group(1)

                result.append({
                    "id": int(offer_raw['id'].split('_')[1]),
                    "sender": int(sender_id) if sender_id is not None else None
                })

        return result
    
    def accept_all_income_offers(self):
        offers = self.get_offers()
        session_id = self.get_session_id()
        tmp_session = self.__session

        # can be better for update
        
        # if offers is None:
        #     self.relogin()
        #     offers = self.get_offers()

        accepted_list = []

        for offer in offers:
            tmp_session.headers.update({
                'Host': 'steamcommunity.com',
                'Origin': 'https://steamcommunity.com',
                'Referer': 'https://steamcommunity.com/tradeoffer/%i/' % offer['id'],
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'same-origin'
            })

            result = tmp_session.post('https://steamcommunity.com/tradeoffer/%i/accept' % offer['id'], data = {
                'sessionid': session_id,
                'serverid': '1',
                'tradeofferid': str(offer['id']),
                'partner': str(offer['sender']),
                'captcha': ''
            })

            if result.status_code == 200:
                print('[STEAM] Offer [%i] for %s has been accepted.' % (offer['id'], self.login))

                accepted_list.append(json.loads(result.text))
            else:
                print('[STEAM] Offer [%i] for %s cant be accepted because status code is %i.' % (offer['id'], self.login, result.status_code))
                print(result.text)

        return accepted_list

    def relogin(self):
        def steam_encode(mod, exp, passwd):
            mod = int(str(mod), 16)
            exp = int(str(exp), 16)
            rsaa = RSA.construct((mod, exp))
            cipher = PKCS1_v1_5.new(rsaa)
            
            return base64.b64encode(cipher.encrypt(passwd))

        session = requests.session()

        for _ in range(THINGS_TRY):
            try:
                keys = json.loads(session.post('https://steamcommunity.com/login/getrsakey/', data = {'donotcache': time.time() * 1000, 'username': self.login}).text)

                if keys and keys.get('success'):
                    tfacode = self.get_auth_code()

                    print('[STEAM] generated 2fa code [%s] for account %s' % (tfacode, self.login))

                    page = session.post('https://steamcommunity.com/login/dologin/', data = {  
                        'donotcache': time.time() * 1000,                                                      
                        'password': steam_encode(keys["publickey_mod"], keys["publickey_exp"], str.encode(self.password)),
                        'username': self.login,
                        'twofactorcode': tfacode,
                        'rsatimestamp': keys['timestamp'],
                        'remember_login': 'true',
                        'captchagid': self.captcha_gid,
                        'emailaut': '',
                        'loginfriendlyname': '',
                        'captcha_text': self.captcha_answer,
                        'emailsteamid': ''
                    })

                    answ = json.loads(page.text)

                    if answ['success'] and answ.get('login_complete'):
                        self.__session = session

                        for cookie in list(session.cookies):
                            for domain in ['store.steampowered.com', 'help.steampowered.com', 'steamcommunity.com']:
                                session.cookies.set(cookie.name, cookie.value, domain=domain, secure=cookie.secure)
                        
                        session_id = self.__get_notify_data()['sessionid']
            
                        for domain in ['store.steampowered.com', 'help.steampowered.com', 'steamcommunity.com']:
                            session.cookies.set('Steam_Language', 'english', domain=domain)
                            session.cookies.set('birthtime', '-3333', domain=domain)
                            session.cookies.set('sessionid', session_id, domain=domain)

                        with open(bot_session_folder + '/%s.session'  % self.login, 'wb') as f:
                            pickle.dump(session.cookies, f)

                        break

                    else:
                        print(answ)

                        if answ.get('captcha_needed', False):
                            self.captcha_gid = answ['captcha_gid']
                            
                            print('https://steamcommunity.com/public/captcha.php?gid=' + answ['captcha_gid'])

                            self.solve_captcha()
                            # time.sleep(35)

                        elif answ.get('message', False) and answ.get('message').find('There have been too many login failures from your network in a short time period.') > -1:
                            print('[STEAM] Account %s has error:\n%s' % (self.login, answ.get('message')))

                            break

                        elif answ.get('requires_twofactor', False):
                            time.sleep(1)
            
            except Exception as e:
                print('[STEAM] Exceptions on steam auth %s' % self.login)
                print(e)
                time.sleep(uniform(1, 5))

        return self.__session

    def __get_steam_session(self):
        session = requests.session()

        try:

            with open(bot_session_folder + '/%s.session'  % self.login, 'rb') as f:
                session.cookies.update(pickle.load(f))

        except IOError:
            pass

        try:
            
            if not self.__get_notify_data(session)['isLogin']:
                print('[STEAM] %s isn\'t login via saved session. Trying relogin.' % self.login)

                self.relogin()
            else:
                self.__session = session

                print('[STEAM] success login %s' % self.login)

        except Exception:
            pass

        return self.__session
    
    def get_session(self):
        isLogin = self.isLogin()

        if not isLogin:
            self.relogin()

        return self.__session

    def get_inventory(self, appid = 730, section = 2):
        answer = None

        steamid_raw = self.__get_notify_data()
        if not steamid_raw or not steamid_raw.get('steamid'):
            return None

        for _ in range(THINGS_TRY):
            try:
                inv_data = self.__session.get("https://steamcommunity.com/inventory/%s/%i/%i" % (steamid_raw['steamid'], appid, section), params = {
                    'l': 'russian',
                    'count': 5000
                }).text

                inv_data = json.loads(inv_data)

                if inv_data.get('success'):
                    answer = {'success': True, 'total': inv_data['total_inventory_count'], 'data': []}
                    
                    if inv_data.get('descriptions') and len(inv_data.get('descriptions')) > 0:
                        for item in inv_data['descriptions']:
                            spec = ''

                            if item.get('owner_descriptions'):
                                for own_descr in item['owner_descriptions']:
                                    spec += '%s\n' % own_descr['value']

                            answer['data'].append({
                                'ru_name': item['market_name'],
                                'en_name': item['market_hash_name'],
                                'spec_data': spec.strip()
                            })

                    break
                else:
                    time.sleep(uniform(1, 5))

            except Exception as e:
                print(e)
                print('[STEAM] Problem with getting steam inventory %s' % self.login)
                time.sleep(uniform(1, 5))

        return answer

    def get_market_sales(self):
        answer = None

        for _ in range(THINGS_TRY):
            try:
                market_data = self.__session.get('https://steamcommunity.com/market/mylistings', params = {
                    "start": 0,
                    "count": 5000
                }).text

                market_data = json.loads(market_data)

                if market_data['success']:
                    answer = {'success': True, 'total': market_data['total_count'], 'data': []}

                    if market_data['total_count'] == 0:
                        break

                    for appid in market_data['assets'].keys():
                        for section in market_data['assets'][appid].keys():
                            for item_id in market_data['assets'][appid][section]:
                                item = market_data['assets'][appid][section][item_id]

                                spec = ''

                                if item.get('owner_descriptions'):
                                    for own_descr in item['owner_descriptions']:
                                        spec += '%s\n' % own_descr['value']

                                spec.strip()

                                answer['data'].append({
                                    'ru_name': item['market_name'],
                                    'en_name': item['market_hash_name'],
                                    'spec_data': spec
                                })
                    
                    break
                else:
                    time.sleep(uniform(1, 5))
            except Exception:
                print('Problem with getting market data %s [STEAM]' % self.login)
                time.sleep(uniform(1, 5))
    
        return answer

    def get_steamid3(self):
        return int(self.get_uid()) - 76561197960265728

    def steamid3to64(self, steamid3):
        return 76561197960265728 + steamid3

    def create_new_trade_link(self):
        new_token = self.__session.post('https://steamcommunity.com/profiles/%s/tradeoffers/newtradeurl' % str(self.get_uid()), 
            data = {'sessionid': self.get_session_id()}).text
        
        return 'https://steamcommunity.com/tradeoffer/new/?partner=%i&token=%s' % (self.get_steamid3(), new_token[1:-1])

    def get_all_steam_items(self):
        appid = 730
        contextid = 2

        for _ in range(10):
            try:
                data = json.loads(self.__session.get("https://steamcommunity.com/profiles/%s/inventory/json/730/2/?trading=1" % self.steam_id).text)
                
                if data is not None:
                    items = []

                    if data.get('rgInventory') is not None:
                        for item_id in data['rgInventory']:
                            items.append({
                                "appid": str(appid),
                                "contextid": str(contextid),
                                "amount": str(data['rgInventory'][item_id]['amount']),
                                "assetid": str(data['rgInventory'][item_id]['id'])
                            })

                    return items
                else:
                    time.sleep(uniform(20, 30))

            except Exception as e:
                print(e)
                time.sleep(uniform(10, 15))

        return None

    def parse_trade_url(self, trade_url):
        matches = re.findall(r"https://steamcommunity\.com/tradeoffer/new/\?partner=(\d+)&token=([a-zA-Z0-9\-]+)", trade_url, re.MULTILINE)

        result = {'steamid3': None, 'steamid64': None, "token": None}

        if len(matches) > 0:
            result = {'steamid3': int(matches[0][0]), 'steamid64': self.steamid3to64(int(matches[0][0])), "token": matches[0][1]}

        return result

    def send_all_items_to(self, tradelink):
        items = self.get_all_steam_items()

        if items is None:
            print('[STEAM] Cant get items for %s' % self.login)
            return None
        
        elif len(items) == 0:
            print('[STEAM] %s has no items for trading' % self.login)
            return None
        
        parsed_trade_url = self.parse_trade_url(tradelink)

        self.__session.headers.update({
            'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Host': 'steamcommunity.com',
            'Origin' : 'https://steamcommunity.com',
            'Referer' : tradelink,
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin'
        })

        items_string = ""

        for item in items:
            items_string += '{"appid":%s,"contextid":"%s","amount":%s,"assetid":"%s"},' % (item['appid'], item['contextid'], item['amount'], item['assetid'])

        items_string = items_string[:-1]

        time.sleep(uniform(1, 1.5))

        for _ in range(THINGS_TRY):
            try:
                result = self.__session.post('https://steamcommunity.com/tradeoffer/new/send', 
                    data = {
                        'sessionid': self.get_session_id(),
                        'serverid': 1,
                        "partner": parsed_trade_url['steamid64'],
                        'tradeoffermessage': "",
                        "json_tradeoffer": '{"newversion":true,"version":3,"me":{"assets":[%s],"currency":[],"ready":false},"them":{"assets":[],"currency":[],"ready":false}}' % items_string,
                        "captcha": "",
                        "trade_offer_create_params": '{"trade_offer_access_token":"%s"}' % parsed_trade_url['token']
                    })

                print(result)

                if result.status_code == 200:
                    break
            except Exception as e:
                print(e)
                time.sleep(10)

        try:
            trade_id = json.loads(result.text)['tradeofferid']
            toc = self.trade_offer_confirm(trade_id)

            print(toc)

            return toc
        except Exception as e:
            print(self.login)
            print(result.text)
            print(e)

        return None

    def trade_offer_confirm(self, tradeid):
        ce = ConfirmationExecutor(self.ident, self.steam_id, self.get_session())

        return ce.send_trade_allow_request(tradeid)

# def get_folder_files(folder):
#     import os

#     for root, dirs, files in os.walk(folder):
#         return files

# for file_ in get_folder_files('bots/'):
#     file_ = open('bots/' + file_, 'r')
#     bot_data = json.loads(file_.read())
#     file_.close()


#     steam = Steam(bot_data['login'], bot_data['password'], bot_data['secret'], bot_data['ident'], True)

#     steam.send_all_items_to('https://steamcommunity.com/tradeoffer/new/?partner=66453550&token=1Dkq8RCN')

#     time.sleep(uniform(20, 25))