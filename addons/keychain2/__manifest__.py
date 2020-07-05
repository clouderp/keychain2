{
    "name": "Keychain2",
    "summary": "Store account credentials",
    "version": "0.0.1",
    "category": "Uncategorized",
    "website": "https://github.com/phlax/keychain2/",
    "author": "Ryan Northey",
    "license": "GPL-3",
    "application": False,
    "installable": True,
    "preloadable": False,
    "external_dependencies": {
        "python": [
            'cryptography'],
    },
    "depends": [
        "base"
    ],
    "data": [
        "security/ir.model.access.csv",
        'views/keychain_view.xml'
    ],
}
