/****************************************************************************
** ui.h extension file, included from the uic-generated form implementation.
**
** If you want to add, delete, or rename functions or slots, use
** Qt Designer to update this file, preserving your code.
**
** You should not define a constructor or destructor in this file.
** Instead, write your code in functions called init() and destroy().
** These will automatically be called by the form's constructor and
** destructor.
*****************************************************************************/


enum {
    AUTH_NONE = 0,
    AUTH_IEEE8021X = 1,
    AUTH_WPA_PSK = 2,
    AUTH_WPA_EAP = 3,
    AUTH_WPA2_PSK = 4,
    AUTH_WPA2_EAP = 5
};

void NetworkConfig::init()
{
    wpagui = NULL;
}

void NetworkConfig::paramsFromScanResults(QListViewItem *sel)
{
    /* SSID BSSID frequency signal flags */
    setCaption(sel->text(0));
    ssidEdit->setText(sel->text(0));
    
    QString flags = sel->text(4);
    int auth, encr = 0;
    if (flags.find("[WPA2-EAP") >= 0)
	auth = AUTH_WPA2_EAP;
    else if (flags.find("[WPA-EAP") >= 0)
	auth = AUTH_WPA_EAP;
    else if (flags.find("[WPA2-PSK") >= 0)
	auth = AUTH_WPA2_PSK;
    else if (flags.find("[WPA-PSK") >= 0)
	auth = AUTH_WPA_PSK;
    else
	auth = AUTH_NONE;
    
    if (flags.find("-CCMP") >= 0)
	encr = 1;
    else if (flags.find("-TKIP") >= 0)
	encr = 0;
    else if (flags.find("WEP") >= 0)
	encr = 1;
    else
	encr = 0;
 
    authSelect->setCurrentItem(auth);
    authChanged(auth);
    encrSelect->setCurrentItem(encr);
}


void NetworkConfig::authChanged(int sel)
{
    pskEdit->setEnabled(sel == AUTH_WPA_PSK || sel == AUTH_WPA2_PSK);
    bool eap = sel == AUTH_IEEE8021X || sel == AUTH_WPA_EAP ||
	       sel == AUTH_WPA2_EAP;
    eapSelect->setEnabled(eap);
    identityEdit->setEnabled(eap);
    passwordEdit->setEnabled(eap);
   
    while (encrSelect->count())
	encrSelect->removeItem(0);
    
    if (sel == AUTH_NONE || sel == AUTH_IEEE8021X) {
	encrSelect->insertItem("None");
	encrSelect->insertItem("WEP");
	encrSelect->setCurrentItem(sel == AUTH_NONE ? 0 : 1);
    } else {
	encrSelect->insertItem("TKIP");
	encrSelect->insertItem("CCMP");
	encrSelect->setCurrentItem((sel == AUTH_WPA2_PSK ||
				    sel == AUTH_WPA2_EAP) ? 1 : 0);
    }
}


void NetworkConfig::addNetwork()
{
    char reply[10], cmd[256];
    size_t reply_len;
    int id;
    int psklen = pskEdit->text().length();
    int auth = authSelect->currentItem();

    if (auth == AUTH_WPA_PSK || auth == AUTH_WPA2_PSK) {
	if (psklen < 8 || psklen > 64) {
	    QMessageBox::warning(this, "wpa_gui", "WPA-PSK requires a passphrase "
				 "of 8 to 63 characters\n"
				 "or 64 hex digit PSK");
	    return;
	}
    }
        
    if (wpagui == NULL)
	return;
    
    memset(reply, 0, sizeof(reply));
    reply_len = sizeof(reply) - 1;
    wpagui->ctrlRequest("ADD_NETWORK", reply, &reply_len);
    if (reply[0] == 'F') {
	QMessageBox::warning(this, "wpa_gui", "Failed to add network to wpa_supplicant\n"
			     "configuration.");
	return;
    }
    id = atoi(reply);

    setNetworkParam(id, "ssid", ssidEdit->text().ascii(), true);
    
    char *key_mgmt = NULL, *proto = NULL, *pairwise = NULL;
    switch (auth) {
    case AUTH_NONE:
	key_mgmt = "NONE";
	break;
    case AUTH_IEEE8021X:
	key_mgmt = "IEEE8021X";
	break;
    case AUTH_WPA_PSK:
	key_mgmt = "WPA-PSK";
	proto = "WPA";
	break;
    case AUTH_WPA_EAP:
	key_mgmt = "WPA-EAP";
	proto = "WPA";
	break;
    case AUTH_WPA2_PSK:
	key_mgmt = "WPA2-PSK";
	proto = "WPA2";
	break;
    case AUTH_WPA2_EAP:
	key_mgmt = "WPA2-EAP";
	proto = "WPA2";
	break;
    }
    
    if (auth == AUTH_WPA_PSK || auth == AUTH_WPA_EAP ||
	auth == AUTH_WPA2_PSK || auth == AUTH_WPA2_EAP) {
	int encr = encrSelect->currentItem();
	if (encr == 0)
	    pairwise = "TKIP";
	else
	    pairwise = "CCMP";
    }
    
    if (proto)
	setNetworkParam(id, "proto", proto, false);
    if (key_mgmt)
	setNetworkParam(id, "key_mgmt", key_mgmt, false);
    if (pairwise) {
	setNetworkParam(id, "pairwise", pairwise, false);
	setNetworkParam(id, "group", "TKIP CCMP WEP104 WEP40", false);
    }
    if (pskEdit->isEnabled())
	setNetworkParam(id, "psk", pskEdit->text().ascii(), psklen != 64);
    if (eapSelect->isEnabled())
	setNetworkParam(id, "eap", eapSelect->currentText().ascii(), false);
    if (identityEdit->isEnabled())
	setNetworkParam(id, "identity", identityEdit->text().ascii(), true);
    if (passwordEdit->isEnabled())
	setNetworkParam(id, "password", passwordEdit->text().ascii(), true);

    snprintf(cmd, sizeof(cmd), "ENABLE_NETWORK %d", id);
    reply_len = sizeof(reply);
    wpagui->ctrlRequest(cmd, reply, &reply_len);
    if (strncmp(reply, "OK", 2) != 0) {
	QMessageBox::warning(this, "wpa_gui", "Failed to enable network in wpa_supplicant\n"
			     "configuration.");
	/* Network was added, so continue anyway */
    }

    close();
}


void NetworkConfig::setWpaGui( WpaGui *_wpagui )
{
    wpagui = _wpagui;
}


int NetworkConfig::setNetworkParam(int id, const char *field, const char *value, bool quote)
{
    char reply[10], cmd[256];
    size_t reply_len;
    snprintf(cmd, sizeof(cmd), "SET_NETWORK %d %s %s%s%s",
	     id, field, quote ? "\"" : "", value, quote ? "\"" : "");
    reply_len = sizeof(reply);
    wpagui->ctrlRequest(cmd, reply, &reply_len);
    return strncmp(reply, "OK", 2) == 0 ? 0 : -1;
}
