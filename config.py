class Config:

    related_work_result_dir = "res/related-works"

    CONTRACT_CREATE_TIME = 'local_res/contract_create_time'

    CI_LOG_FILE = 'local_res/call-injection-analyzer-20190607031718.log'

    CONTRACT_CACHE_PICKLE_FILE = 'local_res/contract_cache'


    token_valuable = [
        '0x8a88f04e0c905054d2f33b26bb3a46d7091a039a',
        '0x74fd51a98a4a1ecbef8cc43be801cce630e260bd',
        '0x0235fe624e044a05eed7a43e16e3083bc8a4287a',
        '0x275b69aa7c8c1d648a0557656bce1c286e69a29d',
        '0x9d9832d1beb29cc949d75d61415fd00279f84dc2',
        '0xf3fe733717ab28cdcb7f2dc22d06c7de858d3edf',
        '0x1f88cac675a37b649646860746f25f58e21b99f2',
        '0xcde3ef6cacf84ad36d8a6eccc964f25351296d36',
        '0xc88be04c809856b75e3dfe19eb4dcf0a3b15317a',
        '0xf69709c4c6f3f2b17978280dce8b7b7a2cbcba8b',
        '0x8faf0be1465b9be70ee73d9123b2a1fdd9f2aae4',
        '0x767588059265d2a243445dd3f23db37b96018dd5',
        '0x3930e4ddb4d24ef2f4cb54c1f009a3694b708428'
    ]

    attack_report_time = {
        'Dao': '2016-06-18',
        'SpankChain': '2018-10-09'
    }

    white_hat_group = {
        '0x69670b0c1b100739812415dd474804bb32b3aeca': 'WHG 1',
        '0x3abe5285ed57c8b028d62d30c456ca9eb3e74105': 'WHG: Choose Return Address',
        '0x1dba1131000664b884a1ba238464159892252d3a': 'WHG: Jordi Baylina',
        '0xac80cba14c08f8a1242ebd0fd45881cfee54b0a2': 'WhiteHatDAOContractController',
        '0xb136707642a4ea12fb4bae820f03d2562ebff487': 'WhiteHatDAO',
        '0x84ef4b2357079cd7a7c69fd7a37cd0609a679106': 'WhitehatDao2',
        '0x2ba9d006c1d72e67a70b5526fc6b4b0c0fd6d334': 'WhiteHatDAOExploitContract'
    }

    dataset_latest_time = {
        'Vandal': '2018-08-30',
        'ZEUS': '2017-03-15 09:45:39',
        'Oyente': '2016-05-05',
        'Securify': '2017-03-04 05:31:21',
        'HoneyBadger': '2018-10-12',
        'teEther': '2017-11-30'
    }

    multi_transfer_function = {
        '0x35bce6e4': 'transferMulti(address[],uint256[])',
        '0x83f12fec': 'batchTransfer(address[],uint256)',
        '0x3badca25': 'batchTransfers(address[],uint256[])',
        '0x1e89d545': 'multiTransfer(address[],uint256[])'
    }
