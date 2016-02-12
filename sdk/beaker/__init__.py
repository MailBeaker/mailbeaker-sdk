import binascii
import json
import logging
import os
import redis
import requests
import time

from requests.exceptions import RequestException
from sdk import jwt
from sdk import sdk_settings
from sdk import stats
from sdk.beaker import mail

import sys
if (sys.version_info > (3, 0)):
    from urllib.parse import urlparse, unquote, urlencode
else:
    from urlparse import urlparse
    from urllib import urlencode
    from urllib2 import unquote

log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())

BEAKER_API_PATHS = {
    'LINKS':            'links/',
    'LINK':             'links/%s/',
    'MESSAGES':         'messages/',
    'MESSAGE':          'messages/%s/',
    'EMAILS':           'emails/%s/',
    'EMAIL':            'emails/?email=%s',
    'SERVICE_MESSAGE':  'messages/?service_message_id=%s',
    'DOMAINS':          'domains/%s/',
    'DOMAIN':           'domains/?domain_name=%s',
    'ORGANIZATIONS':    'organizations/%s/',
    'ORGANIZATION':     'organizations/?domain__domain_name=%s',
    'RULES':            'rules/?domain__domain_name=%s',
    'RULE':             'rules/%s/',
}


class Client(object):

    def __init__(
            self,
            beaker_server=sdk_settings.BEAKER_SERVER_URL,
            beaker_api_username=sdk_settings.BEAKER_API_USERNAME,
            beaker_api_password=sdk_settings.BEAKER_API_PASSWORD,
            link_server=sdk_settings.LINK_SERVER_URL):

        if not beaker_server:
            raise ValueError("Missing Beaker URI")

        if not beaker_api_username or not beaker_api_password:
            raise ValueError("Missing Beaker Credentials")

        self.beaker_server = beaker_server
        self.beaker_api_username = beaker_api_username
        self.beaker_api_password = beaker_api_password
        self.link_server = link_server

        self.redis_client = None
        if sdk_settings.REDIS_ENABLED:
            try:
                self.redis_client = redis.Redis(
                    host=sdk_settings.REDIS_SERVER_HOST,
                    port=sdk_settings.REDIS_SERVER_PORT,
                    password=sdk_settings.REDIS_SERVER_PASSWORD,
                    socket_timeout=sdk_settings.REDIS_SERVER_TIMEOUT,
                    db=0)

                # Test the connection to ensure it really is up.
                self.redis_client.get("TEST_KEY")

            except redis.RedisError:
                log.exception("Exception while attempting to connect to Redis server.")

                # Redis is down, but it was expected to be enabled.
                log.critical("Redis is enabled in the SDK settings (REDIS_ENABLED=True), " \
                             "yet could not be contacted. This thread will now shut down!")

                raise RuntimeError("A failure in Redis caused the thread to abort.")
        else:
            log.critical("Redis is currently disabled in the SDK settings (REDIS_ENABLED=False). " \
                         "Without Redis, no caching will take place, drastically increasing DB lookups. " \
                         "Do NOT ignore this warning in a production environment!")

    @stats.timer('sdk.beaker.get')
    def get(self, path='', cache_maxage=300, cache_nonevalues=True, params=None, headers=None, timeout=15):
        """
        Makes an authenticated GET request to Beaker.

        :param path: The part of the URL to request after the domain.
        :param cache_maxage: The max time-to-live for the object in the Redis cache.
        :param cache_nonevalues: A boolean declaring whether or not to cache Beaker misses ('None' values).
        :param params: A dictionary of query params for the request
        :param headers: A dict of request headers.
        :raises
        :return: JSON response.
        """

        if not headers:
            headers = {}

        if params:
            encoded = urlencode(params)
            request_url = os.path.join(self.beaker_server, path, '?%s' % encoded)
        else:
            request_url = os.path.join(self.beaker_server, path)

        if self.redis_client:
            try:
                redis_result = self.redis_client.get(request_url)
                if redis_result:
                    return json.loads(redis_result.decode('utf-8'))
            except redis.RedisError:
                log.exception("Exception while attempting to get a key from the Redis server.")

        response = requests.get(
            request_url,
            headers=headers,
            timeout=timeout,
            auth=(self.beaker_api_username, self.beaker_api_password)
        )

        if response.status_code < 200 or response.status_code > 299:
            response_data = None
            try:
                response_data = response.text
            except:
                pass
            log.info("Beaker GET: " + request_url, extra={"response": response_data, "request_status": response.status_code} )
            raise Exception("Status Code %s: %s" % (response.status_code, response.text))

        # Cache the response in Redis
        response_data = response.json()
        if self.redis_client:
            # Ensure that 'cache_nonevalues' is True if there
            # were no results for a search operation.
            count = response_data.get('count')
            if count and count == 0 and not cache_nonevalues:
                pass
            elif cache_maxage > 0:
                try:
                    self.redis_client.setex(request_url, response.text, cache_maxage)
                except redis.RedisError:
                    log.exception("Exception while attempting to set a key to the Redis server.")

        log.info("Beaker GET: " + request_url, extra={"response": response_data, "request_status": response.status_code} )

        return response_data

    @stats.timer('sdk.beaker.post')
    def post(self, data, path='', headers=None, timeout=15):
        """
        Makes an authenticated POST request to Beaker.

        :param data: dict of POST data.
        :param path: part of the URL to request after the domain.
        :param headers: dict of request headers.
        :raises
        :return: JSON response.
        """
        if not headers:
            headers = {}

        request_url = os.path.join(self.beaker_server, path)

        request_headers = {
            'content-type': 'application/json'
        }
        request_headers.update(headers)

        response = requests.post(
            request_url,
            data=json.dumps(data),
            headers=request_headers,
            timeout=timeout,
            auth=(self.beaker_api_username, self.beaker_api_password)
        )

        if response.status_code < 200 or response.status_code > 299:
            response_data = None
            try:
                response_data = response.text
            except:
                pass
            log.info("Beaker POST: " + request_url, extra={"request": data, "response": response_data, "request_status": response.status_code} )
            raise Exception("Status Code %s: %s" % (response.status_code, response.text))

        response_data = response.json()
        log.info("Beaker POST: " + request_url, extra={"request": data, "response": response_data, "request_status": response.status_code} )

        return response_data

    @stats.timer('sdk.beaker.patch')
    def patch(self, data, path='', headers=None, timeout=15):
        """
        Makes an authenticated PATCH request to Beaker.

        :param data: dict of PATCH data.
        :param path: part of the URL to request after the domain.
        :param headers: dict of request headers.
        :raises
        :return: JSON response.
        """
        if not headers:
            headers = {}

        request_url = os.path.join(self.beaker_server, path)

        request_headers = {
            'content-type': 'application/json'
        }
        request_headers.update(headers)

        response = requests.patch(
            request_url,
            data=json.dumps(data),
            headers=request_headers,
            timeout=timeout,
            auth=(self.beaker_api_username, self.beaker_api_password)
        )

        if response.status_code < 200 or response.status_code > 299:
            response_data = None
            try:
                response_data = response.text
            except:
                pass
            log.info("Beaker PATCH: " + request_url, extra={"request": data, "response": response_data, "request_status": response.status_code} )
            raise Exception("Status Code %s: %s" % (response.status_code, response.text))

        response_data = response.json()
        log.info("Beaker PATCH: " + request_url, extra={"request": data, "response": response_data, "request_status": response.status_code} )

        return response_data

    @stats.timer('sdk.beaker.generate_replacement_links')
    def generate_replacement_links(self, urls, message_id, domain_id, email=None):
        """
        Generates a bulk set of replacement links for the provided URLs.

        :param urls: A list of url strings.
        :param message_id: The ID of the Message we're generating links for.
        :param domain_id: The ID of the Domain we're generating links for.
        :return: A tuple containing a list of the new Link IDs and a list of the new URLs.
        """
        link_ids_list = list()
        link_list = list()

        for url in urls:
            u = urlparse(url)
            payload = {
                'redirect_url': unquote(url) if url else url,
                'domain':  domain_id,
                'message': message_id,
                'scheme':  u.scheme,
                'netloc': u.netloc,
                'path': unquote(u.path) if u.path else u.path,
                'params': unquote(u.params) if u.params else u.params,
                'query': unquote(u.query) if u.query else u.query,
                'fragment': unquote(u.fragment) if u.fragment else u.fragment,
                'username': u.username,
                'password': u.password,
                'hostname': u.hostname,
                'port': u.port
            }

            try:
                link = self.post(payload, path=BEAKER_API_PATHS['LINKS'])
                link_id = link["id"]
            except RequestException:
                log.exception("Error while attempting to generate Link.")
                # The JWT will be valid, but the ID won't, and the Link
                # server will just assume a database error occurred and will move on.
                link_id = None

            link = self.create_url_from_link_id(link_id, url)

            link_ids_list.append(link_id)
            link_list.append(link)

        return link_ids_list, link_list

    @stats.timer('sdk.beaker.create_url_from_link_id')
    def create_url_from_link_id(self, link_id, url):
        """
        Generates the url that the link server will serve for the link.

        :param link_id: The link ID to create a final URL for.
        :param url: The final URL to redirect the user to.
        :return: The final, valid URL to be served by the link server.
        """

        claims = {
            # These are short to keep the JWT small.
            'i': link_id,
            'u': url,
        }
        link_jwt = jwt.encode_jwt(claims, version=1)
        link_url = "%s%s/" % (self.link_server, link_jwt)

        return link_url

    def mark_link_with_rule(self, rule_id, link_id):
        """
        Associates a Link to a matched Rule.

        :param rule_id: The matched Rule ID.
        :param link_id: The Link ID which was matched to the Rule.
        """
        path = BEAKER_API_PATHS['RULE'] % rule_id
        path = path + "matches"

        payload = {
            'link': link_id,
            'rule': rule_id
        }

        try:
            rule_match = self.post(payload, path=path)
        except RequestException:
            log.exception("Error while attempting to save a Rule match.")

    @stats.timer('sdk.beaker.get_rule')
    def get_rule(self, rule_id, cache_maxage=300):
        """
        Gets a rule entity on the server.

        :param rule_id: The ID of the rule to retrieve.
        :param cache_maxage: The max time-to-live for the object in the Redis cache.
        :return: The Rule represented by the given rule_id.
        """
        path = BEAKER_API_PATHS['RULE'] % rule_id

        try:
            data = self.get(path, cache_maxage=cache_maxage)
        except RequestException:
            log.exception("Error while attempting to query database for Rule information.")
            raise IOError()

        if data.get('id'):
            return data

        return None

    @stats.timer('sdk.beaker.get_link')
    def get_link(self, link_id, cache_maxage=300):
        """
        Gets a Link object.

        :param link_id: The ID of the link to retrieve.
        :param cache_maxage: The max time-to-live for the object in the Redis cache.
        :return: The link represented by the given link_id.
        """
        path = BEAKER_API_PATHS['LINK'] % link_id

        try:
            data = self.get(path, cache_maxage=cache_maxage)
        except RequestException:
            log.exception("Error while attempting to query database for Link information.")
            raise IOError()

        if data.get('id'):
            return data

        return None

    @stats.timer('sdk.beaker.create_message')
    def create_message(self, payload):
        """
        Creates a Message object.

        :param payload: A dictionary of values to save to the database.
        :return: The newly created Message object.
        """

        try:
            message = self.post(payload, path=BEAKER_API_PATHS['MESSAGES'])
        except RequestException:
            log.exception("Error while attempting to save Message information.")
            raise IOError()

        if not message.get('id'):
            return None

        message_id = message.get('id')
        service_message_id = message.get('service_message_id')

        # We are also going to include a signed JWT in the response.
        # This 'Signed ID' will be placed in the final message header,
        # and will be tamper evident.
        claims = {
            'i': message_id,
            's': service_message_id,
        }
        message["signed_id"] = jwt.encode_jwt(claims, version=1)
        return message

    @stats.timer('sdk.beaker.update_email')
    def update_email(self, email_id, payload):
        """
        Updates an Email object.

        :param payload: A dictionary of values to save to the database.
        :return: The updated Email object.
        """

        path = BEAKER_API_PATHS['EMAILS'] % email_id

        try:
            email = self.patch(payload, path=path)
        except RequestException:
            log.exception("Error while attempting to update Email information.")
            raise IOError()

        if not email.get('id'):
            return None

        return email

    @stats.timer('sdk.beaker.get_email_by_address')
    def get_email_by_address(self, address, cache_maxage=0):
        """
        Gets an Email object.

        :param address: The e-mail address of the Beaker Email object.
        :param cache_maxage: The max time-to-live for the object in the Redis cache.
        :return: The Email respresented by the given address.
        """
        path = BEAKER_API_PATHS['EMAIL'] % address

        try:
            data = self.get(path, cache_maxage=cache_maxage)
        except RequestException:
            log.exception("Error while attempting to query database for Email information.")
            raise IOError()

        if not data.get('results'):
            return None

        if len(data['results']) < 1:
            return None

        return data['results'][0]

    @stats.timer('sdk.beaker.update_message')
    def update_message(self, message_id, payload):
        """
        Updates a Message object.

        :param payload: A dictionary of values to save to the database.
        :return: The updated Message object.
        """

        path = BEAKER_API_PATHS['MESSAGE'] % message_id

        try:
            message = self.patch(payload, path=path)
        except RequestException:
            log.exception("Error while attempting to update Message information.")
            raise IOError()

        if not message.get('id'):
            return None

        return message

    @stats.timer('sdk.beaker.get_message')
    def get_message(self, message_id, cache_maxage=300):
        """
        Gets a Message object.

        :param message_id: The ID of the message to retrieve.
        :param cache_maxage: The max time-to-live for the object in the Redis cache.
        :return: The Message represented by the given message_id.
        """
        path = BEAKER_API_PATHS['MESSAGE'] % message_id

        try:
            data = self.get(path, cache_maxage=cache_maxage)
        except RequestException:
            log.exception("Error while attempting to query database for Message information.")
            raise IOError()

        if data.get('id'):
            return data

        return None

    # TODO We can make this a HEAD request, probably, and change the method name
    # to something like check_if_message_existss_by_service_id
    @stats.timer('sdk.beaker.get_message_by_service_id')
    def get_message_by_service_id(self, service_message_id, cache_maxage=300):
        """
        Gets a Message object.

        :param service_message_id: The Service ID (Gmail's ID) of the message to retrieve.
        :param cache_maxage: The max time-to-live for the object in the Redis cache.
        :return: The Message represented by the given message_id.
        """
        path = BEAKER_API_PATHS['SERVICE_MESSAGE'] % service_message_id

        try:
            # 'cache_nonevalues'=False means that if there's no hit, we're not going
            # to cache the value. We want this because we want to cache hits, but
            # check every time for misses.
            data = self.get(path, cache_maxage=cache_maxage, cache_nonevalues=False)
        except RequestException:
            log.exception("Error while attempting to query database for Message information by Service ID.")
            raise IOError()

        if not data.get('results'):
            return None

        if len(data['results']) < 1:
            return None

        return data['results'][0]

    @stats.timer('sdk.beaker.get_domain_by_domain_name')
    def get_domain_by_domain_name(self, domain_name, cache_maxage=300):
        """
        Get the JSON dict for the Domain identified by :param domain_name:

        :param domain_name: The domain name to lookup information for.
        :param cache_maxage: The max time-to-live for the object in the Redis cache.
        :return: JSON dictionary representing the Domain.
        """
        path = BEAKER_API_PATHS['DOMAIN'] % domain_name

        try:
            data = self.get(path, cache_maxage=cache_maxage)
        except RequestException:
            log.exception("Error while attempting to query database for organization information.")
            raise IOError()

        if not data.get('results'):
            return None

        if len(data['results']) < 1:
            return None

        return data['results'][0]

    @stats.timer('sdk.beaker.get_organization_by_domain_name')
    def get_organization_by_domain_name(self, domain_name, cache_maxage=300):
        """
        Get the JSON dict for the Organization identified by :param domain_name:

        :param domain_name: The domain name to lookup information for.
        :param cache_maxage: The max time-to-live for the object in the Redis cache.
        :return: JSON dictionary representing the Organization.
        """
        path = BEAKER_API_PATHS['ORGANIZATION'] % domain_name

        try:
            data = self.get(path, cache_maxage=cache_maxage)
        except RequestException:
            log.exception("Error while attempting to query database for organization information.")
            raise IOError()

        if not data.get('results'):
            return None

        if len(data['results']) < 1:
            return None

        return data['results'][0]

    @stats.timer('sdk.beaker.get_users_by_organization')
    def get_users_by_organization(self, organization_id, cache_maxage=300):
        """
        Get the JSON dict for the Organization identified by :param organization_id:

        :param organization_id: The ID of the organization to lookup information for.
        :param cache_maxage: The max time-to-live for the object in the Redis cache.
        :return: JSON dictionary representing the Organization.
        """

        path = BEAKER_API_PATHS['ORGANIZATIONS'] % organization_id
        path = path + "users"

        try:
            data = self.get(path, cache_maxage=cache_maxage)
        except RequestException:
            log.exception("Error while attempting to query database for organization user information.")
            raise IOError()

        if not data.get('results'):
            return None

        if len(data['results']) < 1:
            return None

        return data['results']

    @stats.timer('sdk.beaker.get_users_by_domain')
    def get_users_by_domain(self, domain_id, cache_maxage=300):
        """
        Get the JSON dict for the Domain users identified by :param domain_id:

        :param domain_id: The ID of the Domain to lookup information for.
        :param cache_maxage: The max time-to-live for the object in the Redis cache.
        :return: JSON dictionary representing the users of the Domain.
        """

        path = BEAKER_API_PATHS['DOMAINS'] % domain_id
        path = path + "users"

        try:
            data = self.get(path, cache_maxage=cache_maxage)
        except RequestException:
            log.exception("Error while attempting to query database for organization user information.")
            raise IOError()

        if not data.get('results'):
            return None

        if len(data['results']) < 1:
            return None

        return data['results']

    @stats.timer('sdk.beaker.get_rules_by_domain')
    def get_rules_by_domain(self, domain_id, cache_maxage=60):
        """
        Get the JSON dict for the Domain rules identified by :param domain_id:

        :param domain_id: The ID of the Domain to lookup information for.
        :param cache_maxage: The max time-to-live for the object in the Redis cache.
        :return: JSON dictionary representing the Rules of the Domain.
        """

        path = BEAKER_API_PATHS['RULES'] % domain_id

        try:
            data = self.get(path, cache_maxage=cache_maxage)
        except RequestException:
            log.exception("Error while attempting to query database for domain rules information.")
            raise IOError()

        if not data.get('results'):
            return None

        if len(data['results']) < 1:
            return None

        return data['results']

    @stats.timer('sdk.beaker.check_rules')
    def check_rules(self, message_from_address, domain_id, domain_name, link_ids,
                    senders=None, receivers=None, subject=None, body=None, urls=None):
        """
        The function that checks this Message for matching Domain rules and flags Links accordingly.

        :param message_from_address: The 'From' header value.
        :param domain_id: The ID for the Domain of the recipient of this Message.
        :param domain_name: The Domain Name of the recipient of this Message.
        :param link_ids: A list of Link IDs contained in this Message.
        :param senders: An optional list of senders (such as 'From' header and 'MAIL FROM' envelope sender).
        :param receivers: An optional list of receivers (such as the 'To', 'Cc', or 'RCPT TO' envelope receiver).
        :param subject: An optional subject to compare against.
        :param body: An optional message body (message text) to compare against.
        :param urls: An optional list of URLs to compare against.
        :return: A dictionary of Link keys and matching Rule values.
        """
        link_rules_dict = dict()
        rules = self.get_rules_by_domain(domain_name)

        if not rules:
            return link_rules_dict

        # Get all the values we could potentially match against
        # TODO make sure that non-URL matches (like body text) mark all links as matches.
        comparison_dict = dict()

        if senders:
            comparison_dict['sender'] = senders
        if receivers:
            comparison_dict['receiver'] = receivers
        if subject:
            comparison_dict['subject'] = subject
        if body:
            comparison_dict['body'] = body
        if urls:
            comparison_dict['url'] = urls

        # Per each rule in the domain's rules
        for domain_rule in rules:
            domain_rule_id = domain_rule["id"]

            total_items_in_rule = 0
            total_matches_in_rule = 0
            link_ids_to_flag = list()

            # For each type of possible rule, and the values those rules would match against
            for rule_class, comparator in comparison_dict.items():

                # For each rule class, check the DB and see if the admin created a rule in that class
                # with a modifier (e.g. "starts with") and value.
                if (domain_rule[rule_class + "_mod"] and domain_rule[rule_class + "_mod"] > 0) and \
                        (domain_rule[rule_class + "_value"] and len(domain_rule[rule_class + "_value"]) > 0):

                    total_items_in_rule += 1

                    # If this item isn't a list, make it one
                    if not isinstance(comparator, list):
                        comparator = [comparator]

                    mod = domain_rule[rule_class + "_mod"]
                    value = domain_rule[rule_class + "_value"].lower()

                    # At this point, we have a rule, we have a rule class (e.g. "Subject"), and now
                    # we need to check the 'compare' field, which contains the value(s) to inspect.
                    for i, compare in enumerate(comparator):
                        total_matches_before_check = total_matches_in_rule
                        compare = compare.lower()

                        if mod == 1 and value == compare:  # Equal to
                            total_matches_in_rule += 1
                        elif mod == 2 and value != compare:  # Not equal to
                            total_matches_in_rule += 1
                        elif mod == 3 and value in compare:  # Contains
                            total_matches_in_rule += 1
                        elif mod == 4 and value not in compare:  # Does not contain
                            total_matches_in_rule += 1
                        elif mod == 5 and compare.startswith(value):  # Starts with
                            total_matches_in_rule += 1
                        elif mod == 6 and compare.endswith(value):  # Ends with
                            total_matches_in_rule += 1

                        # A match was found in the item inspected.
                        # If it was a link, we need to note its link ID
                        if total_matches_in_rule != total_matches_before_check:
                            if rule_class == "url":
                                link_ids_to_flag.append(link_ids[i])

            # If all criteria the user specified for this rule were matched in the checks above,
            # then we need to perform the user's desired action
            if total_items_in_rule > 0 and total_matches_in_rule >= total_items_in_rule:

                # If a URL component (the link destination) was part of the
                # criteria for fulfilling this rule, mark the link docs individually.
                if len(link_ids_to_flag) > 0:
                    suspect_ids = link_ids_to_flag

                # If a message component (subject, sender, etc) was the only criteria that matched,
                # find all the URLs and mark them
                else:
                    suspect_ids = link_ids

                for link_id in suspect_ids:
                    # For this link ID, create a dict we can store information inside of,
                    # if one doesn't already exist.
                    if link_id not in link_rules_dict:
                        link_rules_dict[link_id] = dict()
                        link_rules_dict[link_id]['rule_ids'] = list()

                    link_rules_dict[link_id]['rule_ids'].append(domain_rule_id)

                # Is this a rule which requires alerting the admins?
                if domain_rule["alert_admins"]:
                    # The admin will only care about people in their org who get the
                    # suspicious message, so we remove all other recipients from 'outside'
                    # domains from the notification.
                    org_recipients = list()

                    if receivers:
                        for recipient in receivers:
                            if recipient.endswith(domain_name):
                                org_recipients.append(recipient)

                    admin_emails = self.get_organization_user_emails(domain_id)

                    message_subject = "(subject not available)"
                    if subject:
                        message_subject = subject
                    mail.send_rule_match_alert(admin_emails, org_recipients, message_from_address,
                                               message_subject, domain_rule["description"])

        return link_rules_dict

    @stats.timer('sdk.beaker.save_auth_token')
    def save_auth_token(self, service, email, access_token, expiration):
        if not self.redis_client:
            return

        if not expiration:
            expiration = 3600  # 1hr, the default for Google.
            log.error("No token expiration provided by service '%s', assuming %d." % (service, expiration))

        try:
            self.redis_client.setex("auth_token:%s_%s" % (service, email),
                                    access_token, (expiration - 120))  # Clear two minutes early, just to be safe.
        except redis.RedisError:
            log.exception("Exception while attempting to set a key to the Redis server.")

    def get_auth_token(self, service, email):
        if not self.redis_client:
            return None

        try:
            redis_result = self.redis_client.get("auth_token:%s_%s" % (service, email))
            if redis_result:
                return redis_result.decode('utf-8')
        except redis.RedisError:
            log.exception("Exception while attempting to get a key from the Redis server.")

        return None

    @stats.timer('sdk.beaker.clear_auth_token')
    def clear_auth_token(self, service, email):
        if not self.redis_client:
            return

        try:
            self.redis_client.delete("auth_token:%s_%s" % (service, email))
        except redis.RedisError:
            log.exception("Exception while attempting to delete a key from the Redis server.")

    @stats.timer('sdk.beaker.save_message_lock')
    def save_message_lock(self, service_message_id):
        if not self.redis_client:
            return

        try:
            self.redis_client.setex("message_lock:%s" % service_message_id, 1, 3600)
        except redis.RedisError:
            log.exception("Exception while attempting to set a key to the Redis server.")

    @stats.timer('sdk.beaker.get_message_lock')
    def get_message_lock(self, service_message_id):
        if not self.redis_client:
            return

        try:
            redis_result = self.redis_client.get("message_lock:%s" % service_message_id)
            if redis_result:
                return redis_result.decode('utf-8')
        except redis.RedisError:
            log.exception("Exception while attempting to get a key from the Redis server.")

    @stats.timer('sdk.beaker.get_organization_user_emails')
    def get_organization_user_emails(self, domain_id):
        """
        Get the e-mail addresses for all users in the Organization identified by :param domain_id:

        :param domain_id: The ID of the Domain to lookup information for.
        :return: List of e-mail addresses for users in the Organization.
        """

        if not domain_id:
            return []

        users = self.get_users_by_domain(domain_id)
        emails = list()

        if not users:
            return []

        for user in users:
            emails.append(user["email"])

        return emails
