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


import os
from xml.etree import ElementTree

from .user import User, UserException


class TranslationFile(User):
    """ Encapsulate a translation file. """

    def __init__(self, ts_file, no_obsolete, no_summary, **kwargs):
        """ Initialise the translation file. """

        super().__init__(**kwargs)

        if os.path.isfile(ts_file):
            self.progress("Reading {0}...".format(ts_file))

            try:
                self._root = ElementTree.parse(ts_file).getroot()
            except Exception as e:
                raise UserException(
                        "{}: {}: {}".format(ts_file,
                                "invalid translation file", str(e)))
        else:
            self._root = ElementTree.fromstring(_EMPTY_TS)

        self._ts_file = ts_file
        self._no_obsolete = no_obsolete
        self._no_summary = no_summary
        self._updated_contexts = {}

        # Create a dict of contexts keyed by the context name and having the
        # list of message elements as the value.
        self._contexts = {}

        # Also create a dict of existing translations so that they can be
        # re-used.
        self._translations = {}

        context_els = []
        for context_el in self._root:
            if context_el.tag != 'context':
                continue

            context_els.append(context_el)

            name = ''
            message_els = []

            for el in context_el:
                if el.tag == 'name':
                    name = el.text
                elif el.tag == 'message':
                    message_els.append(el)

            if name:
                self._contexts[name] = message_els

                for message_el in message_els:
                    source_el = message_el.find('source')
                    if source_el is None or not source_el.text:
                        continue

                    translation_el = message_el.find('translation')
                    if translation_el is None or not translation_el.text:
                        continue

                    self._translations[source_el.text] = translation_el.text

        # Remove the context elements but keep everything else in the root
        # (probably set by Linguist).
        for context_el in context_els:
            self._root.remove(context_el)

        # Clear the summary statistics.
        self._nr_new = 0
        self._nr_new_duplicates = 0
        self._nr_new_using_existing_translation = 0
        self._nr_existing = 0
        self._nr_kept_obsolete = 0
        self._nr_discarded_obsolete = 0
        self._nr_discarded_untranslated = 0

        # Remember all new messages so we can make the summary less confusing
        # than it otherwise might be.
        self._new_message_els = []

    def update(self, source):
        """ Update the translation file from a SourceFile object. """

        self.progress(
                "Updating {0} from {1}...".format(self._ts_file,
                        source.filename))

        for context in source.contexts:
            # Get the messages that we already know about for this context.
            try:
                message_els = self._contexts[context.name]
            except KeyError:
                message_els = []

            # Get the messages that have already been updated.
            updated_message_els = self._get_updated_message_els(context.name)

            for message in context.messages:
                message_el = self._find_message(message, message_els)

                if message_el is not None:
                    # Move the message to the updated list.
                    message_els.remove(message_el)
                    self._add_message_el(message_el, updated_message_els)
                else:
                    # See if this is a new message.  If not then we just have
                    # another location for an existing message.
                    message_el = self._find_message(message,
                         updated_message_els)

                if message_el is None:
                    message_el = self._make_message_el(message)
                    updated_message_els.append(message_el)

                    self.progress(
                            "Added new message '{0}'".format(
                                    self.pretty(message.source)))
                    self._nr_new += 1
                else:
                    self.progress(
                            "Updated message '{0}'".format(
                                    self.pretty(message.source)))

                    # Go through any translations making sure they are not
                    # 'vanished' which might happen if we have restored a
                    # previously obsolete message.
                    for translation_el in message_el.findall('translation'):
                        if translation_el.get('type') == 'vanished':
                            if translation_el.text:
                                del translation_el.attrib['type']
                            else:
                                translation_el.set('type', 'unfinished')

                    # Don't count another copy of a new message as an existing
                    # one.
                    if message_el in self._new_message_els:
                        self._nr_new_duplicates += 1
                    else:
                        self._nr_existing += 1

                message_el.insert(0, self._make_location_el(message))

    def write(self):
        """ Write the translation file back to the filesystem. """

        # If we are keeping obsolete messages then add them to the updated
        # message elements list.
        for name, message_els in self._contexts.items():
            updated_message_els = None

            for message_el in message_els:
                source = self.pretty(message_el.find('source').text)

                translation_el = message_el.find('translation')
                if translation_el is not None and translation_el.text:
                    if self._no_obsolete:
                        self.progress(
                                "Discarded obsolete message '{0}'".format(
                                        source))
                        self._nr_discarded_obsolete += 1
                    else:
                        translation_el.set('type', 'vanished')

                        if updated_message_els is None:
                            updated_message_els = self._get_updated_message_els(
                                    name)

                        self._add_message_el(message_el, updated_message_els)

                        self.progress(
                                "Kept obsolete message '{0}'".format(source))
                        self._nr_kept_obsolete += 1
                else:
                    self.progress(
                            "Discarded untranslated message '{0}'".format(
                                    source))
                    self._nr_discarded_untranslated += 1

        # Created the sorted context elements.
        for name in sorted(self._updated_contexts.keys()):
            context_el = ElementTree.Element('context')

            name_el = ElementTree.Element('name')
            name_el.text = name
            context_el.append(name_el)

            context_el.extend(self._updated_contexts[name])

            self._root.append(context_el)

        self.progress("Writing {0}...".format(self._ts_file))

        # Replicate the indentation used by Qt Linguist.  Note that there are
        # still differences in the way elements are closed.
        for el in self._root:
            ElementTree.indent(el, space='    ')

        with open(self._ts_file, 'w', encoding='utf-8', newline='\n') as f:
            f.write('<?xml version="1.0" encoding="utf-8"?>\n')
            f.write('<!DOCTYPE TS>\n')
            ElementTree.ElementTree(self._root).write(f, encoding='unicode')
            f.write('\n')

        if not self._no_summary:
            self._summary()

    @staticmethod
    def _add_message_el(message_el, updated_message_els):
        """ Add a message element to a list of updated message elements. """

        # Remove all the location elements.
        for location_el in message_el.findall('location'):
            message_el.remove(location_el)

        # Add the message to the updated list.
        updated_message_els.append(message_el)

    @classmethod
    def _find_message(cls, message, message_els):
        """ Return the message element for a message from a list. """

        for message_el in message_els:
            source = ''
            comment = ''
            extra_comment = ''
            extras = []

            # Extract the data from the element.
            for el in message_el:
                if el.tag == 'source':
                    source = el.text
                elif el.tag == 'comment':
                    comment = el.text
                elif el.tag == 'extracomment':
                    extra_comment = el.text
                elif el.tag.startswith('extra-'):
                    extras.append([el.tag[6:], el.text])

            # Compare with the message.
            if source != message.source:
                continue

            if comment != message.comment:
                continue

            if extra_comment != cls._get_message_extra_comments(message):
                continue

            if extras != message.embedded_comments.extras:
                continue

            return message_el

        return None

    @staticmethod
    def _get_message_extra_comments(message):
        """ Return a message's extra comments as they appear in a .ts file. """

        return ' '.join(message.embedded_comments.extra_comments)

    def _get_updated_message_els(self, name):
        """ Return the list of updated message elements for a context. """

        try:
            updated_message_els = self._updated_contexts[name]
        except KeyError:
            updated_message_els = []
            self._updated_contexts[name] = updated_message_els

        return updated_message_els

    def _make_location_el(self, message):
        """ Return a 'location' element. """

        return ElementTree.Element('location',
                filename=os.path.relpath(message.filename,
                        start=os.path.dirname(os.path.abspath(self._ts_file))),
                line=str(message.line_nr))

    def _make_message_el(self, message):
        """ Return a 'message' element. """

        attrs = {}

        if message.embedded_comments.message_id:
            attrs['id'] = message.embedded_comments.message_id

        if message.numerus:
            attrs['numerus'] = 'yes'

        message_el = ElementTree.Element('message', attrs)

        source_el = ElementTree.Element('source')
        source_el.text = message.source
        message_el.append(source_el)

        if message.comment:
            comment_el = ElementTree.Element('comment')
            comment_el.text = message.comment
            message_el.append(comment_el)

        if message.embedded_comments.extra_comments:
            extracomment_el = ElementTree.Element('extracomment')
            extracomment_el.text = self._get_message_extra_comments(message)
            message_el.append(extracomment_el)

        translation_el = ElementTree.Element('translation',
                type='unfinished')

        # Try and find another message with the same source and use its
        # translation if it has one.
        translation = self._translations.get(message.source)
        if translation:
            translation_el.text = translation

            self.progress(
                    "Reused existing translation for '{0}'".format(
                            self.pretty(message.source)))
            self._nr_new_using_existing_translation += 1

        if message.numerus:
            translation_el.append(ElementTree.Element(
                    'numerusform'))

        message_el.append(translation_el)

        for field, value in message.embedded_comments.extras:
            el = ElementTree.Element('extra-' + field)
            el.text = value
            message_el.append(el)

        self._new_message_els.append(message_el)

        return message_el

    def _summary(self):
        """ Display the summary of changes to the user. """

        summary_lines = []

        # Display a line of the summary and the heading if not already done.
        def summary(line):
            nonlocal summary_lines

            if not summary_lines:
                summary_lines.append(
                        "Summary of changes to {ts}:".format(ts=self._ts_file))

            summary_lines.append("    " + line)

        if self._nr_new:
            if self._nr_new_duplicates:
                summary("{0} new messages were added (and {1} duplicates)".format(
                        self._nr_new, self._nr_new_duplicates))
            else:
                summary("{0} new messages were added".format(self._nr_new))

        if self._nr_new_using_existing_translation:
            summary("{0} messages reused existing translations".format(
                    self._nr_new_using_existing_translation))

        if self._nr_existing:
            summary("{0} existing messages were found".format(
                    self._nr_existing))

        if self._nr_kept_obsolete:
            summary("{0} obsolete messages were kept".format(
                    self._nr_kept_obsolete))

        if self._nr_discarded_obsolete:
            summary("{0} obsolete messages were discarded".format(
                    self._nr_discarded_obsolete))

        if self._nr_discarded_untranslated:
            summary("{0} untranslated messages were discarded".format(
                    self._nr_discarded_untranslated))

        if not summary_lines:
            summary_lines.append("{ts} was unchanged".format(ts=self._ts_file))

        print(os.linesep.join(summary_lines))


# The XML of an empty .ts file.  This is what a current lupdate will create
# with an empty C++ source file.
_EMPTY_TS = '''<TS version="2.1">
</TS>
'''
