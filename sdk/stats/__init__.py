import logging
import statsd

from sdk import sdk_settings


statsd_client = None

if sdk_settings.STATSD_ENABLED:
    try:
        statsd_client = statsd.StatsClient(host=sdk_settings.STATSD_SERVER_HOST,
                                           port=sdk_settings.STATSD_SERVER_PORT)
    except:
        logging.exception("Creation of statsd client failed.")


def timing(stat, delta, rate=1):
    """
    Sends new timing information to the server.

    :param stat: The name of the timer to use.
    :param delta: The amount of time the operation took to complete, in milliseconds.
    :param rate: A sample rate, a float between 0 and 1. Will only send data this percentage of the time.
    """
    if not statsd_client:
        return

    try:
        statsd_client.timing(stat, delta, rate)
    except:
        logging.exception("Call to 'timing' stat failed.")


def incr(stat, count=1, rate=1):
    """
    Increments a stat.

    :param stat: The name of the stat to increment.
    :param count: The amount to increment by. Typically an integer, and may be negative.
    :param rate: A sample rate, a float between 0 and 1. Will only send data this percentage of the time.
    """
    if not statsd_client:
        return

    try:
        statsd_client.incr(stat, count, rate)

    except:
        logging.exception("Call to 'incr' stat failed.")


def timer(name, rate=1):
    """
    Automatically record timing information for a managed block or function call.

    :param stat: The name of the stat to increment.
    :param rate: A sample rate, a float between 0 and 1. Will only send data this percentage of the time.
    """
    def do_nothing(f):
        return f

    if statsd_client:
        return statsd_client.timer(name, rate)
    else:
        # In the event that the statsd client isn't available,
        # we return an empty function to ensure the decorator doesn't break.
        return do_nothing
