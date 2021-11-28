from xkcdpass import xkcd_password as xp
# taken from https://github.com/redacted/XKCD-password-generator
# create a wordlist from the default wordfile
# use words between 4 and 9 letters long
def gen_xkcd():
    wordfile = xp.locate_wordfile()
    mywords = xp.generate_wordlist(wordfile=wordfile, min_length=4, max_length=9)

    # create a password with the acrostic "face"
    passwd = xp.generate_xkcdpassword(mywords)
    print(passwd)
    return passwd
