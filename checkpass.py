import requests
import hashlib
import sys

def req_api_data(query):
	url = 'https://api.pwnedpasswords.com/range/' + query
	res = requests.get(url)
	if res.status_code !=200:
		raise RuntimeError(f'Error fetching : {res.status_code}, Check the api')
	return res

def pass_leak_count(hashes, hash_check):
	hashes = (line.split(':') for line in hashes.text.splitlines())
	for h,count in hashes:
		if h==hash_check:
			return count
	return 0


def pwned_api_check(password):
	sha1pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
	first_five_chars , tail = sha1pass[:5], sha1pass [5:]
	response = req_api_data(first_five_chars)
	return pass_leak_count(response,tail)

def main(args):
	for password in args:
		count = pwned_api_check(password)
		if count:
			print(f'{password} was found {count} number of times.... and this is why you should probably change your password')
		else:
			print(f'{password} was NOT found')

	return 'Done!'

if __name__ == '__main__':
	sys.exit(main(sys.argv[1:]))
