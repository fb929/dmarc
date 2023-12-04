# dmarc
download and analyze dmarc reports

## for gmail you need enable access for "less secure apps"
https://support.google.com/a/answer/6260879?hl=en

## usage
### install pip modules
```
pip install -r requirements.txt
```

### create config file ./.config.yaml
```
email:
  address: yourEmailAddr@gmail.com
  password: "secret"
  server: imap.gmail.com
searchLimitDays: 30 # days for search limit. if not set, will download all emails
inboxSelect: dmarc # inbox dir for search, by default "INBOX"
```
### run
```
./dmarcReports.py
```

