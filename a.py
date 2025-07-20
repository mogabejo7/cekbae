import threading
import queue
import random
import time
import os
from web3 import Web3, HTTPProvider
from eth_account import Account
from hexbytes import HexBytes
import logging
from typing import List, Tuple
import requests
from concurrent.futures import ThreadPoolExecutor
from urllib3.exceptions import HTTPError

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Config
CONFIG = {
    'RPC_URL': "https://testnet.dplabs-internal.com",
    'CONTROLLER_ADDRESS': "0x51be1ef20a1fd5179419738fc71d95a8b6f8a175",
    'DURATION': 31536000,
    'RESOLVER': "0x9a43dcA1C3BB268546b98eb2AB1401bFc5b58505",
    'DATA': [],
    'REVERSE_RECORD': True,
    'OWNER_CONTROLLED_FUSES': 0,
    'MAX_CONCURRENCY': 10
}

FAILED_FILE = 'failed.txt'
MAX_TOTAL_RETRY = 3  # Retry maksimum untuk batch domain gagal

# ABI minimal
CONTROLLER_ABI = [
    {
        "constant": True, "inputs": [{"name": "name", "type": "string"}, {"name": "owner", "type": "address"}, {"name": "duration", "type": "uint256"}, {"name": "secret", "type": "bytes32"}, {"name": "resolver", "type": "address"}, {"name": "data", "type": "bytes[]"}, {"name": "reverseRecord", "type": "bool"}, {"name": "ownerControlledFuses", "type": "uint16"}],
        "name": "makeCommitment", "outputs": [{"name": "", "type": "bytes32"}], "stateMutability": "pure", "type": "function"
    },
    {
        "constant": False, "inputs": [{"name": "commitment", "type": "bytes32"}], "name": "commit", "outputs": [], "stateMutability": "nonpayable", "type": "function"
    },
    {
        "constant": True, "inputs": [{"name": "name", "type": "string"}, {"name": "duration", "type": "uint256"}],
        "name": "rentPrice", "outputs": [{"components": [{"name": "base", "type": "uint256"}, {"name": "premium", "type": "uint256"}], "name": "", "type": "tuple"}], "stateMutability": "view", "type": "function"
    },
    {
        "constant": False, "inputs": [{"name": "name", "type": "string"}, {"name": "owner", "type": "address"}, {"name": "duration", "type": "uint256"}, {"name": "secret", "type": "bytes32"}, {"name": "resolver", "type": "address"}, {"name": "data", "type": "bytes[]"}, {"name": "reverseRecord", "type": "bool"}, {"name": "ownerControlledFuses", "type": "uint16"}],
        "name": "register", "outputs": [], "stateMutability": "payable", "type": "function"
    }
]

def load_file_lines(filename: str) -> List[str]:
    try:
        with open(filename, 'r') as f:
            return [line.strip().lower() for line in f if line.strip()]
    except FileNotFoundError:
        logger.error(f"File {filename} tidak ditemukan")
        return []

def save_failed_domain(domain: str):
    with open(FAILED_FILE, 'a') as f:
        f.write(domain + '\n')

def clear_failed_file():
    if os.path.exists(FAILED_FILE):
        os.remove(FAILED_FILE)

def load_failed_domains() -> List[str]:
    return load_file_lines(FAILED_FILE)

def test_proxy(proxy: str) -> bool:
    try:
        response = requests.get('https://api.ipify.org', proxies={'http': proxy, 'https': proxy}, timeout=5)
        return response.status_code == 200
    except (requests.RequestException, HTTPError):
        return False

def create_web3_instance(proxy: str = None) -> Web3:
    if proxy:
        session = requests.Session()
        session.proxies = {'http': proxy, 'https': proxy}
        return Web3(HTTPProvider(CONFIG['RPC_URL'], session=session))
    return Web3(HTTPProvider(CONFIG['RPC_URL']))

def validate_private_key(private_key: str) -> bool:
    if private_key.startswith('0x'):
        private_key = private_key[2:]
    return len(private_key) == 64 and all(c in '0123456789abcdefABCDEF' for c in private_key)

def register_domain(private_key: str, name: str, task_index: int, proxy: str = None) -> None:
    MAX_RETRY = 5
    retry = 0

    if not validate_private_key(private_key):
        logger.error(f"[Tugas #{task_index}] Kunci privat tidak valid untuk domain {name}.phrs")
        return

    w3 = create_web3_instance(proxy)

    try:
        controller_address = w3.to_checksum_address(CONFIG['CONTROLLER_ADDRESS'])
        resolver_address = w3.to_checksum_address(CONFIG['RESOLVER'])
    except ValueError as e:
        logger.error(f"[Tugas #{task_index}] Alamat tidak valid dalam konfigurasi: {e}")
        return

    while retry < MAX_RETRY:
        try:
            account = Account.from_key(private_key)
            controller = w3.eth.contract(address=controller_address, abi=CONTROLLER_ABI)

            owner = account.address
            secret = '0x' + os.urandom(32).hex()

            logger.info(f"[Tugas #{task_index}] Wallet: {owner}, Nama: {name}.phrs")

            commitment = controller.functions.makeCommitment(
                name, owner, CONFIG['DURATION'], HexBytes(secret),
                resolver_address, CONFIG['DATA'], CONFIG['REVERSE_RECORD'],
                CONFIG['OWNER_CONTROLLED_FUSES']).call()
            logger.info(f"[Tugas #{task_index}] Commitment: {commitment.hex()}")

            tx = controller.functions.commit(commitment).build_transaction({
                'from': owner, 'nonce': w3.eth.get_transaction_count(owner),
                'gas': 200000, 'gasPrice': w3.eth.gas_price})
            signed_tx = w3.eth.account.sign_transaction(tx, private_key)
            tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            w3.eth.wait_for_transaction_receipt(tx_hash)
            logger.info(f"[Tugas #{task_index}] Commitment terkirim untuk {name}.phrs")

            logger.info(f"[Tugas #{task_index}] Menunggu 60 detik...")
            time.sleep(60)

            price = controller.functions.rentPrice(name, CONFIG['DURATION']).call()
            value = price[0] + price[1]
            logger.info(f"[Tugas #{task_index}] Harga untuk {name}.phrs: {w3.from_wei(value, 'ether')} ETH")

            tx = controller.functions.register(
                name, owner, CONFIG['DURATION'], HexBytes(secret),
                resolver_address, CONFIG['DATA'], CONFIG['REVERSE_RECORD'],
                CONFIG['OWNER_CONTROLLED_FUSES']).build_transaction({
                    'from': owner, 'nonce': w3.eth.get_transaction_count(owner),
                    'gas': 300000, 'gasPrice': w3.eth.gas_price, 'value': value})
            signed_tx = w3.eth.account.sign_transaction(tx, private_key)
            tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            w3.eth.wait_for_transaction_receipt(tx_hash)
            logger.info(f"✅ [Tugas #{task_index}] {name}.phrs berhasil didaftarkan")
            break

        except Exception as err:
            retry += 1
            msg = str(err)[:120] + '...' if len(str(err)) > 120 else str(err)
            if retry < MAX_RETRY:
                logger.warning(f"[Tugas #{task_index}] Error pada {name}.phrs: {msg} - retry {retry}/{MAX_RETRY}...")
                time.sleep(60)
            else:
                logger.error(f"❌ [Tugas #{task_index}] Gagal mendaftarkan {name}.phrs setelah {MAX_RETRY} kali: {msg}")
                save_failed_domain(name)
                break

def main():
    pk_list = load_file_lines("pk.txt")
    proxy_list = [proxy for proxy in load_file_lines("proxy.txt") if test_proxy(proxy)]

    if not pk_list:
        logger.error("pk.txt kosong. Bot berhenti.")
        return

    original_domain_list = load_file_lines("domain.txt")
    if not original_domain_list:
        logger.error("domain.txt kosong. Bot berhenti.")
        return

    domain_list = original_domain_list.copy()
    attempt = 1

    while attempt <= MAX_TOTAL_RETRY:
        clear_failed_file()
        tasks = []
        for i, domain_name in enumerate(domain_list):
            pk_untuk_tugas_ini = pk_list[i % len(pk_list)]
            tasks.append((pk_untuk_tugas_ini, domain_name, i + 1))

        logger.info(f"🔁 Percobaan #{attempt} — {len(tasks)} domain...")
        with ThreadPoolExecutor(max_workers=CONFIG['MAX_CONCURRENCY']) as executor:
            futures = [executor.submit(register_domain, pk, name, task_idx,
                                       random.choice(proxy_list) if proxy_list else None)
                       for pk, name, task_idx in tasks]
            for future in futures:
                future.result()

        domain_list = load_failed_domains()
        if not domain_list:
            logger.info("🎉 Semua domain berhasil didaftarkan.")
            break
        else:
            logger.warning(f"❗ Gagal: {len(domain_list)} domain. Retry setelah 60 detik...")
            attempt += 1
            time.sleep(60)

    if domain_list:
        logger.error("🚫 Masih ada domain gagal. Lihat failed.txt.")

if __name__ == "__main__":
    main()
