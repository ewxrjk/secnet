# Python argparse --[no-]foo options
#
# Copyright 2012 "Omnifarious" (a user on StackOverFlow)
# Copyright 2013 "btel" (a user on StackOverFlow)
#
# https://stackoverflow.com/questions/9234258/in-python-argparse-is-it-possible-to-have-paired-no-something-something-arg/20422915#20422915
#
# CC-BY-SA 4.0
# by virtue of
# https://stackoverflow.com/legal/terms-of-service#licensing
# which says everything is CC-BY-SA and has a link to v4.0
# (And which is therefore compatible with secnet's GPLv3+)
#
# all retrieved 4.11.2019

import argparse

class ActionNoYes(argparse.Action):
    def __init__(self, option_strings, dest, default=None, required=False, help=None):

        if default is None:
            raise ValueError('You must provide a default with Yes/No action')
        if len(option_strings)!=1:
            raise ValueError('Only single argument is allowed with YesNo action')
        opt = option_strings[0]
        if not opt.startswith('--'):
            raise ValueError('Yes/No arguments must be prefixed with --')

        opt = opt[2:]
        opts = ['--' + opt, '--no-' + opt]
        super(ActionNoYes, self).__init__(opts, dest, nargs=0, const=None, 
                                          default=default, required=required, help=help)
    def __call__(self, parser, namespace, values, option_strings=None):
        if option_strings.startswith('--no-'):
            setattr(namespace, self.dest, False)
        else:
            setattr(namespace, self.dest, True)
