# -*- coding: utf-8 -*-
import smtplib

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from sdk import sdk_settings

def send_rule_match_alert(alert_recipients, message_recipients, from_email, subject, rule_description):

    msg = MIMEMultipart('alternative')
    msg['From'] = "MailBeaker Notifications <notifications@mailbeaker.com>"
    msg['Subject'] = "MailBeaker rule '%s' triggered" % rule_description

    recipients_string = ""
    for recipient in message_recipients:
        recipients_string = "%s%s%s" % (recipients_string, recipient, "\n")

    text = """
Hello!

MailBeaker recently received a message matching the following rule:
%s

Subject: %s
From: %s
To: %s

You are being contacted because you (or another administrator in your organization) enabled alerting for each time a message is received that matches this rule.

If you have any questions or concerns, please feel free to reach out to us at support@mailbeaker.com

Thanks,
The MailBeaker Team
    """

    html = """
  <div text="#000000" bgcolor="#FFFFFF">
    <div dir="ltr">
      <table style="color:rgb(51,51,51);font-family:Helvetica,Arial,sans-serif;font-size:14px;line-height:19px;border-bottom-width:1px;border-bottom-style:dashed;border-bottom-color:rgb(237,237,237)" width="100%%" align="center" border="0" cellpadding="0" cellspacing="0">
        <tbody>
          <tr>
            <td>
              <table width="600" align="center" border="0" cellpadding="0" cellspacing="0">
                <tbody>
                  <tr>
                    <td style="padding:0px 20px" height="40">
                      <p style="font-size:12px;line-height:16px;font-family:Helvetica,Arial,sans-serif;color:rgb(153,153,153)">This is an automated e-mail, please do not reply.</p>
                    </td>
                  </tr>
                </tbody>
              </table>
            </td>
          </tr>
        </tbody>
      </table>
      <table style="color:rgb(51,51,51);font-family:Helvetica,Arial,sans-serif;font-size:14px;line-height:19px" width="600" align="center" border="0" cellpadding="0" cellspacing="0">
        <tbody>
          <tr>
            <td style="padding:20px">
              <div style="font-family:Helvetica,Arial,sans-serif">
                Hello!<br /><br />MailBeaker recently received a message matching the following rule:<br />
                <strong>'%s'</strong><br /><br />
                Subject: %s<br />
                From: %s<br />
                To: %s
                <br /><br />
                You are being contacted because you (or another administrator
                in your organization) enabled alerting for each time a message
                is received that matches this rule.<br>
                <br>
                If you have any questions or concerns, please feel free to reach
                out to us at support@mailbeaker.com
              </div>
            </td>
          </tr>
        </tbody>
      </table>
      <table style="color:rgb(51,51,51);font-family:Helvetica,Arial,sans-serif;font-size:14px;line-height:19px" width="600" align="center" border="0" cellpadding="0" cellspacing="0">
        <tbody>
          <tr>
            <td style="padding:30px 20px 20px">
              <p style="font-weight:bold;font-size:16px;line-height:24px;font-family:Helvetica,Arial,sans-serif;color:rgb(102,102,102);margin:0px">Thanks,<br>
                The MailBeaker Team</p>
            </td>
          </tr>
        </tbody>
      </table>
      <table style="color:rgb(51,51,51);font-family:Helvetica,Arial,sans-serif;font-size:14px;line-height:19px" width="600" align="center" border="0" cellpadding="0" cellspacing="0">
        <tbody>
          <tr>
            <td style="padding:20px 20px 40px;border-top-width:1px;border-top-style:solid;border-top-color:rgb(237,237,237)">
              <p style="font-size:11px;font-family:Helvetica,Arial,sans-serif;color:rgb(181,181,181);margin-bottom:15px">
                MailBeaker staff will never ask you for your password via email.
                Be alert to emails that request account information or
                urgent action. Be cautious of websites with irregular
                addresses or those that claim to be affiliated with MailBeaker.
                <br /><br />
                <strong>&copy; 2015 MailBeaker</strong>
              </p>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
    """

    # For 1 recipient, do single line. For any more than that, do multiple lines.
    if len(message_recipients) > 1:
        recipients_string = "\n" + recipients_string

    text = text % (rule_description, subject, from_email, recipients_string)
    html = html % (rule_description, subject, from_email, recipients_string.replace("\n", "<br />"))

    plaintext_part = MIMEText(text, 'plain')
    html_part = MIMEText(html, 'html')
    msg.attach(plaintext_part)
    msg.attach(html_part)

    for recipient in alert_recipients:
        msg['To'] = recipient
        send_message(msg)

def send_message(msg):
    s = smtplib.SMTP(sdk_settings.EXTERNAL_EMAIL_HOST, 587)
    s.login(sdk_settings.EXTERNAL_EMAIL_USERNAME, sdk_settings.EXTERNAL_EMAIL_PASSWORD)
    s.sendmail(msg['From'], msg['To'], msg.as_string())
