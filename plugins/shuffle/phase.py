class Phase(object):

    phases = frozenset([
      'Announcement', # Everone generates new encryption keys and distributes them to one another.
      'Shuffling', # In turn, each of the players adds his own new address and reshufles the result.
      'BroadcastOutput', # The final output order is broadcast to everyone.
      'EquivocationCheck', # Check that everyone has the same set of inputs.
      'Signing',
      'VerificationAndSubmission', # Generate transaction, distribute signatures, and send it off.
      'Blame'])

    def __init__(self):
        self.__phase = 'Uninitiated'

    @property
    def phase(self):
        return self.__phase

    @phase.setter
    def phase(self,value):
        if value in self.phases:
            self.__phase = value
        else:
            raise ValueError("No such phase")

    def __init__(self, value):
        if value in self.phases:
            self.__phase = value
        else:
            raise ValueError("No such phase")
