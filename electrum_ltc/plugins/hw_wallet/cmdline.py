from electrum_ltc.util import print_msg, print_error, raw_input


class CmdLineHandler:

    def get_passphrase(self, msg, confirm):
        import getpass
        print_msg(msg)
        return getpass.getpass('')

    def get_pin(self, msg):
        t = { 'a':'7', 'b':'8', 'c':'9', 'd':'4', 'e':'5', 'f':'6', 'g':'1', 'h':'2', 'i':'3'}
        print_msg(msg)
        print_msg("a b c\nd e f\ng h i\n-----")
        o = raw_input()
        try:
            return ''.join(map(lambda x: t[x], o))
        except KeyError as e:
            raise Exception("Character {} not in matrix!".format(e)) from e

    def prompt_auth(self, msg):
        import getpass
        print_msg(msg)
        response = getpass.getpass('')
        if len(response) == 0:
            return None
        return response

    def yes_no_question(self, msg):
        print_msg(msg)
        return raw_input() in 'yY'

    def stop(self):
        pass

    def show_message(self, msg, on_cancel=None):
        print_msg(msg)

    def show_error(self, msg, blocking=False):
        print_msg(msg)

    def update_status(self, b):
        print_error('hw device status', b)

    def finished(self):
        pass
