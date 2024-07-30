"""Backup script for tumblr blogs."""
from __future__ import annotations

import json
import pprint
import time
import sys
from typing import Any
from typing import TypedDict

import pytumblr2
import requests_oauthlib
from requests_oauthlib import OAuth1Session


class CredentialSet(TypedDict):
    consumer_key: str
    consumer_secret: str
    oauth_token: str
    oauth_secret: str



def get_oauth(cred: CredentialSet) -> tuple[str, str]:
    """Get oauth tokens for given creds."""
    request_token_url = "http://www.tumblr.com/oauth/request_token"
    authorize_url = "http://www.tumblr.com/oauth/authorize"
    access_token_url = "http://www.tumblr.com/oauth/access_token"

    # STEP 1: Obtain request token
    oauth_session = OAuth1Session(
        cred["consumer_key"], client_secret=cred["consumer_secret"],
    )
    fetch_response = oauth_session.fetch_request_token(request_token_url)
    try:
        resource_owner_key = fetch_response.get("oauth_token")
        resource_owner_secret = fetch_response.get("oauth_token_secret")
    except requests_oauthlib.oauth1_session.TokenRequestDenied:
        print("Your consumer key and secret key didn't work; please try again!")
        sys.exit(1)

    # STEP 2: Authorize URL + Response
    full_authorize_url = oauth_session.authorization_url(authorize_url)

    # Redirect to authentication page
    print(f"\nPlease go here and authorize:\n{full_authorize_url}")
    redirect_response = input("Allow then paste the full redirect URL here:\n").strip()

    # Retrieve oauth verifier
    oauth_response = oauth_session.parse_authorization_response(redirect_response)

    verifier = oauth_response.get("oauth_verifier")

    # STEP 3: Request final access token
    oauth_session = OAuth1Session(
        cred["consumer_key"],
        client_secret=cred["consumer_secret"],
        resource_owner_key=resource_owner_key,
        resource_owner_secret=resource_owner_secret,
        verifier=verifier,
    )
    oauth_tokens = oauth_session.fetch_access_token(access_token_url)

    oauth_token:str = oauth_tokens.get("oauth_token")
    oauth_token_secret:str = oauth_tokens.get("oauth_token_secret")
    return oauth_token, oauth_token_secret


def get_saved_creds() -> dict[str, CredentialSet]:
    """Return dict of creds.

    creds is a dict where each key is the blog name and each value is a dict with the
    keys consumer_key, consumer_secret, oauth_token, oauth_secret
    """
    try:
        with open("creds.json") as f:
            creds = json.loads(f.read())
    except FileNotFoundError:
        creds: dict[str, CredentialSet] = {}
    except json.decoder.JSONDecodeError:
        if len(sys.argv) > 2 and sys.argv[2] == "-f":
            with open("creds.json", "w") as f:
                f.write(json.dumps({}))
        else:
            print(
                "Credentials corrupted. Run 'python3 main.py register -f' to create a new file, or fix the credentials yourself.",
            )
            sys.exit(1)

    return creds


def create_client(cred: CredentialSet) -> Any:
    client = pytumblr2.TumblrRestClient(
        cred["consumer_key"],
        cred["consumer_secret"],
        cred["oauth_token"],
        cred["oauth_secret"],
    )

    client.npf_consumption_on()

    return client


def register() -> None:
    """Get the OAuth creds for a new blog."""
    creds = get_saved_creds()

    if creds == {}:
        create_new = input("No credentials found. Create new? [Y/n]")
    else:
        create_new = input(
            f"Credentials found - {', '.join([name for name in creds.keys()])}. Create new? [Y/n]",
        )

    if create_new == "n":
        sys.exit(0)

    print(
        "If you haven't already, please go to https://api.tumblr.com/console and register a new application for your blog. For more details, run 'python3 main.py help --app.",
    )
    cred_name = input("Blog name: ")
    while cred_name in creds:
        cred_name = input("That name is already taken. Please enter another: ").strip()
    creds[cred_name] = {}
    creds[cred_name]["consumer_key"] = input("Consumer key: ").strip()
    creds[cred_name]["consumer_secret"] = input("Consumer secret: ").strip()
    creds[cred_name]["oauth_token"], creds[cred_name]["oauth_secret"] = get_oauth(creds[cred_name])

    client = create_client(creds[cred_name])
    try:
        print(f"Blog {client.info()['user']['name']} registered successfully.")
        with open("creds.json", "w") as f:
            f.write(json.dumps(creds))
    except ValueError:
        print("Failed to register blog. Please try again.")


def backup() -> None:
    """Perform a backup."""
    creds: dict[str, CredentialSet] = get_saved_creds()

    if len(creds.keys()) > 1:
        print(
            f"You have multiple credentials saved. Please select which one to backup [{list(creds.keys())[0]}]: ",
        )
        for i, blog_name in enumerate(creds.keys()):
            print(f"{i}) {blog_name}\n")
        blog_to_backup = input()
        if blog_to_backup == "":
            blog_to_backup: str = list(creds.keys())[0]
        elif blog_to_backup.isdigit():
            blog_to_backup = list(creds.keys())[int(blog_to_backup)]

        while blog_to_backup not in creds:
            blog_to_backup = input(
                "Please select a blog to backup [{creds.keys()[0]}]: ",
            )
            if blog_to_backup == "":
                blog_to_backup = list(creds.keys())[0]
            elif blog_to_backup.isdigit():
                blog_to_backup = list(creds.keys())[int(blog_to_backup)]
    else:
        blog_to_backup = list(creds.keys())[0]


    client = create_client(creds[blog_to_backup])

    this_backup = {"following": [], "likes": []}

    client_info = client.info()

    # Followers
    num_following = client_info["user"]["following"]
    offset = 0
    limit = 20

    """
    print("Beginning follower backup...")
    while len(this_backup["following"]) < num_following:
        print(f"Requesting batch {int(offset/20)+1} of {int(num_following/20)+1}.")
        this_batch = client.following(offset=offset, limit=limit)

        for blog in this_batch["blogs"]:
            print(blog["name"], end=", ")
            this_backup["following"].append(blog["name"])

        print()
        try:
            offset = int(this_batch["_links"]["next"]["query_params"]["offset"])
        except KeyError:
            limit = num_following-len(this_backup["following"])+1
        time.sleep(1)

    this_backup["following"] = list(set(this_backup["following"]))
    print(f"Finished follower backup, backed up {len(this_backup['following'])} of {num_following}.")

    # Likes
    num_likes = client_info["user"]["likes"]
    limit = 20
    before = time.time()

    print("Beginning likes backup...")
    while len(this_backup["likes"]) < num_likes:
        gmtime = time.gmtime(before)
        print(f"Requesting likes before {time.strftime('%Y-%m-%d %H:%M:%S', gmtime)}.")
        this_batch = client.likes(before=before, limit=limit)

        for like in this_batch["liked_posts"]:
            this_backup["likes"].append(like["post_url"])

        try:
            before = int(this_batch["_links"]["next"]["query_params"]["before"])
        except KeyError:
            break
    print(f"Finished likes backup, backed up {len(this_backup['likes'])} of {num_likes}.")
    """

    # Posts
    num_posts = client_info["user"]["likes"]
    print("Beginning posts backup...")

    this_batch = client.posts(blog_to_backup)["posts"]
    for post in this_batch:
        save_data = {}
        pprint.pprint(post)

        # Reblogs
        if "parent_post_url" in post:
            save_data["content"] = post["content"]
            save_data["layout"] = post["layout"]

            save_data["reblog_key"] = post["reblog_key"]
            save_data["reblog_blog"] = post["trail"][-1]["blog"]["name"]
            save_data["reblog_uuid"] = post["trail"][-1]["blog"]["uuid"]
            save_data["post_id"] = post["trail"][-1]["post"]["id"]

            client.reblog_post(blog_to_backup, save_data["reblog_blog"], save_data["post_id"], content=save_data["content"], layout=save_data["layout"], parent_blog_uuid=save_data["reblog_uuid"], reblog_key=save_data["reblog_key"])

        time.sleep(1)

    with open(f"{blog_to_backup}.json", "w") as f:
        f.write(json.dumps(this_backup))


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("""
BlogUp - Back Up Your Tumblr Blog

Please run with the register or backup argument.""")
        sys.exit()

    if sys.argv[1] == "register":
        register()
    elif sys.argv[1] == "backup":
        backup()
