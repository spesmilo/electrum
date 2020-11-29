def get_contacts(wallet):
    return sorted(wallet.contacts.get_all(), key=lambda contact: contact.name)
