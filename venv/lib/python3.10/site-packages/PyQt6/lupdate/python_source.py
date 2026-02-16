# Copyright (c) 2026 Riverbank Computing Limited <info@riverbankcomputing.com>
# 
# This file is part of PyQt6.
# 
# This file may be used under the terms of the GNU General Public License
# version 3.0 as published by the Free Software Foundation and appearing in
# the file LICENSE included in the packaging of this file.  Please review the
# following information to ensure the GNU General Public License version 3.0
# requirements will be met: http://www.gnu.org/copyleft/gpl.html.
# 
# If you do not wish to use this file under the terms of the GPL version 3.0
# then you may purchase a commercial license.  For more information contact
# info@riverbankcomputing.com.
# 
# This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
# WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.


import ast
import re
import tokenize

from .source_file import SourceFile
from .translations import Context, EmbeddedComments, Message
from .user import User, UserException


class PythonSource(SourceFile, User):
    """ Encapsulate a Python source file. """

    # The regular expression to extract a PEP 263 encoding.
    _PEP_263 = re.compile(rb'^[ \t\f]*#.*?coding[:=][ \t]*([-_.a-zA-Z0-9]+)')

    def __init__(self, **kwargs):
        """ Initialise the object. """

        super().__init__(**kwargs)

        # Read the source file.
        self.progress("Reading {0}...".format(self.filename))
        with open(self.filename, 'rb') as f:
            source = f.read()

        # Implement universal newlines.
        source = source.replace(b'\r\n', b'\n').replace(b'\r', b'\n')

        # Try and extract a PEP 263 encoding.
        encoding = 'UTF-8'

        for line_nr, line in enumerate(source.split(b'\n')):
            if line_nr > 1:
                break

            match = re.match(self._PEP_263, line)
            if match:
                encoding = match.group(1).decode('ascii')
                break

        # Decode the source according to the encoding.
        try:
            source = source.decode(encoding)
        except LookupError:
            raise UserException("Unsupported encoding '{0}'".format(encoding))

        # Parse the source file.
        self.progress("Parsing {0}...".format(self.filename))

        try:
            tree = ast.parse(source, filename=self.filename)
        except SyntaxError as e:
            raise UserException(
                    "Invalid syntax at line {0} of {1}:\n{2}".format(
                            e.lineno, e.filename, e.text.rstrip()))

        # Look for translation contexts and their contents.
        visitor = Visitor(self)
        visitor.visit(tree)

        # Read the file again as a sequence of tokens so that we see the
        # comments.
        with open(self.filename, 'rb') as f:
            current = None

            for token in tokenize.tokenize(f.readline):
                if token.type == tokenize.COMMENT:
                    # See if it is an embedded comment.
                    parts = token.string.split(' ', maxsplit=1)
                    if len(parts) == 2:
                        if parts[0] == '#:':
                            if current is None:
                                current = EmbeddedComments()

                            current.extra_comments.append(parts[1])
                        elif parts[0] == '#=':
                            if current is None:
                                current = EmbeddedComments()

                            current.message_id = parts[1]
                        elif parts[0] == '#~':
                            parts = parts[1].split(' ', maxsplit=1)
                            if len(parts) == 1:
                                parts.append('')

                            if current is None:
                                current = EmbeddedComments()

                            current.extras.append(parts)

                elif token.type == tokenize.NL:
                    continue

                elif current is not None:
                    # Associate the embedded comment with the line containing
                    # this token.
                    line_nr = token.start[0]

                    # See if there is a message on that line.
                    for context in self.contexts:
                        for message in context.messages:
                            if message.line_nr == line_nr:
                                break
                        else:
                            message = None

                        if message is not None:
                            message.embedded_comments = current
                            break

                    current = None


class Visitor(ast.NodeVisitor):
    """ A visitor that extracts translation contexts. """

    def __init__(self, source):
        """ Initialise the visitor. """

        self._source = source
        self._context_stack = []

        super().__init__()

    def visit_Call(self, node):
        """ Visit a call. """

        # Parse the arguments if a translation function is being called.
        call_args = None

        if isinstance(node.func, ast.Attribute):
            name = node.func.attr

        elif isinstance(node.func, ast.Name):
            name = node.func.id

            if name == 'QT_TR_NOOP':
                call_args = self._parse_QT_TR_NOOP(node)
            elif name == 'QT_TRANSLATE_NOOP':
                call_args = self._parse_QT_TRANSLATE_NOOP(node)
        else:
            name = ''

        # Allow these to be either methods or functions.
        if name == 'tr':
            call_args = self._parse_tr(node)
        elif name == 'translate':
            call_args = self._parse_translate(node)

        # Update the context if the arguments are usable.
        if call_args is not None and call_args.source != '':
            call_args.context.messages.append(
                    Message(self._source.filename, node.lineno,
                            call_args.source, call_args.disambiguation,
                            (call_args.numerus)))

        self.generic_visit(node)

    def visit_ClassDef(self, node):
        """ Visit a class. """

        try:
            name = self._context_stack[-1].name + '.' + node.name
        except IndexError:
            name = node.name

        self._context_stack.append(Context(name))

        self.generic_visit(node)

        context = self._context_stack.pop()

        if context.messages:
            self._source.contexts.append(context)

    def _get_current_context(self):
        """ Return the current Context object if there is one. """

        return self._context_stack[-1] if self._context_stack else None

    @classmethod
    def _get_first_str(cls, args):
        """ Get the first of a list of arguments as a str. """

        # Check that there is at least one argument.
        if not args:
            return None

        return cls._get_str(args[0])

    def _get_or_create_context(self, name):
        """ Return the Context object for a name, creating it if necessary. """

        for context in self._source.contexts:
            if context.name == name:
                return context

        context = Context(name)
        self._source.contexts.append(context)

        return context

    @staticmethod
    def _get_str(node, allow_none=False):
        """ Return the str from a node or None if it wasn't an appropriate
        node.
        """

        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                return node.value

            if allow_none and node.value is None:
                return ''

        return None

    def _parse_QT_TR_NOOP(self, node):
        """ Parse the arguments to QT_TR_NOOP(). """

        # Ignore unless there is a current context.
        context = self._get_current_context()
        if context is None:
            return None

        call_args = self._parse_noop_without_context(node.args, node.keywords)
        if call_args is None:
            return None

        call_args.context = context

        return call_args

    def _parse_QT_TRANSLATE_NOOP(self, node):
        """ Parse the arguments to QT_TRANSLATE_NOOP(). """

        # Get the context.
        name = self._get_first_str(node.args)
        if name is None:
            return None

        call_args = self._parse_noop_without_context(node.args[1:],
                node.keywords)
        if call_args is None:
            return None

        call_args.context = self._get_or_create_context(name)

        return call_args

    def _parse_tr(self, node):
        """ Parse the arguments to tr(). """

        # Ignore unless there is a current context.
        context = self._get_current_context()
        if context is None:
            return None

        call_args = self._parse_without_context(node.args, node.keywords)
        if call_args is None:
            return None

        call_args.context = context

        return call_args

    def _parse_translate(self, node):
        """ Parse the arguments to translate(). """

        # Get the context.
        name = self._get_first_str(node.args)
        if name is None:
            return None

        call_args = self._parse_without_context(node.args[1:], node.keywords)
        if call_args is None:
            return None

        call_args.context = self._get_or_create_context(name)

        return call_args

    def _parse_without_context(self, args, keywords):
        """ Parse arguments for a message source and optional disambiguation
        and n.
        """

        # The source is required.
        source = self._get_first_str(args)
        if source is None:
            return None

        if len(args) > 1:
            disambiguation = self._get_str(args[1], allow_none=True)
        else:
            for kw in keywords:
                if kw.arg == 'disambiguation':
                    disambiguation = self._get_str(kw.value, allow_none=True)
                    break
            else:
                disambiguation = ''

        # Ignore if the disambiguation is specified but isn't a string.
        if disambiguation is None:
            return None

        if len(args) > 2:
            numerus = True
        else:
            numerus = 'n' in keywords

        if len(args) > 3:
            return None

        return CallArguments(source, disambiguation, numerus)

    def _parse_noop_without_context(self, args, keywords):
        """ Parse arguments for a message source. """

        # There must be exactly one positional argument.
        if len(args) != 1 or len(keywords) != 0:
            return None

        source = self._get_str(args[0])
        if source is None:
            return None

        return CallArguments(source)


class CallArguments:
    """ Encapsulate the possible arguments of a translation function. """

    def __init__(self, source, disambiguation='', numerus=False):
        """ Initialise the object. """

        self.context = None
        self.source = source
        self.disambiguation = disambiguation
        self.numerus = numerus
