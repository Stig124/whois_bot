#!/usr/bin/env python3
import platform
import time
import datetime
import signal

import praw
import whois_alt
import whois
import tld

alternate_whois = None
prefix = "!whois"

red = praw.Reddit("whois_bot")


class BotException(Exception):
    """Base exception class for exceptions that occur within this script."""


class InvalidDomain(BotException):
    """Indicate that an invalid domain vas provided"""


class NotSupportedTLD(BotException):
    """Indicate that a non-supported TLD was processed (when the two"""


class NoDomainProvided(BotException):
    """Indicate that no domain was provided"""


class WHOISTimedOut(BotException):
    """Indicate that whois_alt timed-out"""


if platform.system() == "Windows":
    """
    SIGALRM doesn't exists on Windows, so the whois will never timeout
    """
    print("This bot will not work as intended on Windows, see docs")


def main():
    """Uses the comment stream to find the prefix

    :return:
    """
    for item in red.subreddit("Scams").stream.comments(skip_existing=True):
        if prefix in item.body.lower() and "AutoModerator" != item.author:
            raw = item.body.split(" ")
            try:  # Extract the domain from the URL
                domain = extract_domain(raw=raw)
            except InvalidDomain:  # If an invalid domain was provided, check another comment
                break
            except NoDomainProvided: # If no domain is provided
                break
            try:
                record = get_whois(domain)
            except WHOISTimedOut:
                try:
                    record = get_whois_alt(domain)
                except NoDomainProvided:
                    break
            message = parse_whois(whois_record=record, domain=domain)
            reply(message=message, comment=item)
            break


def extract_domain(raw):
    """Extracts the domain name from the message


    :param raw: list word-scinded list of the message sent
    :return domain: extracted domain
    """
    needs_fixing: bool = True
    for n, i in enumerate(raw):
        if prefix in raw[n - 1]:
            domain: str = i
            needs_fixing: bool = False if "http" in domain else True
    if "domain" in locals():
        test_for_points: list = domain.split(".")
    else:
        raise NoDomainProvided
    if len(test_for_points) > 2:
        try:
            domain: str = tld.get_fld(domain, fix_protocol=needs_fixing)
        except tld.utils.TldBadUrl:
            raise InvalidDomain
        else:
            return domain
    else:
        return domain


def get_whois(domain):
    """Queries Whois for the requested domain

    As whois_alt doesn't support some TLDs, an alternative is needed
    whois_alt never exits if they don't support the TLD, timeouting is needed (and ONLY handled in Unix)
    :param domain: str: domain name extracted by extract_domain
    :return: record
    """
    global alternate_whois
    if platform.system() != "Windows":
        signal.signal(signal.SIGALRM, handler)
        signal.alarm(3)
    try:
        record: dict = whois_alt.get_whois(domain)
    except TimeoutError:
        raise WHOISTimedOut
    else:
        alternate_whois = False
        return record


def get_whois_alt(domain):
    """Alternate

    :param domain:
    :return:
    """
    global alternate_whois
    alternate_whois = True
    record: dict = whois.whois(domain)
    time.sleep(1)
    if record["registrar"] is None:
        raise NotSupportedTLD
    else:
        return record


def parse_whois(whois_record: dict, domain: str):
    """Format the date created to message

    :param whois_record: dict of the whois gotten previously
    :param domain: str domain name
    :return:
    """
    if platform.system() != "Windows":
        signal.alarm(0)
    if alternate_whois is False:
        try:
            date_created: datetime.datetime = whois_record["creation_date"][0]
        except AttributeError:
            date_created: datetime.datetime = whois_record["creation_date"]
    date_created_formatted: str = date_created.strftime("%Y/%m/%d")
    delta: datetime.timedelta = datetime.datetime.now() - date_created
    n_months = delta.days / 30
    n_years = delta.days / 365
    if int(n_years) == 1:
        delta_formatted: str = str(int(n_years)) + " year ago"
    elif n_years > 1:
        delta_formatted: str = str(int(n_years)) + " years ago"
    elif int(n_months) == 1:
        delta_formatted: str = str(int(n_months)) + " month ago"
    elif n_months > 1:
        delta_formatted: str = str(int(n_months)) + " months ago"
    else:
        delta_formatted: str = str(delta.days) + " days ago"
    title: str = "WHOIS for " + domain + "\n\n"
    message_l1: str = domain + " has been created on " + date_created_formatted + "." + "\n"
    message_l2: str = "It means that the domain was created around" + delta_formatted + "\n"
    footer_1: str = (
        "^^^I'm a bot this action was done automatically " + "\n"
    )
    footer_2: str = (
        "^^^If you'd spot bugs or ways to improve please share it on Github, "
        "[click here!](https://github.com/Stig124/whois_bot)"
    )
    message = title + message_l1 + message_l2 + footer_1 + footer_2
    return message

def reply(message: str, comment: praw.Reddit.comment):
    comment.reply(message)


def handler(signum, frame):
    raise TimeoutError


if __name__ == "__main__":
    print(red.user.me())
    main()
