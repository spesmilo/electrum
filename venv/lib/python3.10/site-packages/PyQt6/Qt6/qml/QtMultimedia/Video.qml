// Copyright (C) 2016 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only

import QtQuick
import QtMultimedia

/*!
    \qmltype Video
    \inherits Item
    \ingroup multimedia_qml
    \ingroup multimedia_video_qml
    \inqmlmodule QtMultimedia
    \brief A convenience type for showing a specified video.

    \c Video is a convenience type combining the functionality
    of a \l MediaPlayer and a \l VideoOutput into one. It provides
    simple video playback functionality without having to declare multiple
    types.

    The following is sample code to implement video playback in a scene.

    \qml
    Video {
        id: video
        width : 800
        height : 600
        source: "video.avi"

        MouseArea {
            anchors.fill: parent
            onClicked: {
                video.play()
            }
        }

        focus: true
        Keys.onSpacePressed: video.playbackState == MediaPlayer.PlayingState ? video.pause() : video.play()
        Keys.onLeftPressed: video.position = video.position - 5000
        Keys.onRightPressed: video.position = video.position + 5000
    }
    \endqml

    The source file, \c video.avi, plays when you click the parent
    of MouseArea. The video plays in an area of 800 by 600 pixels, and its \c id
    property has the value \b{video}.

    Notice that because signals for the \l Keys have been defined pressing the:
    \list
    \li \uicontrol Spacebar toggles the pause button.
    \li \uicontrol{Left Arrow} moves the current position in the video to 5 seconds
    previously.
    \li \uicontrol{Right Arrow} advances the current position in the video by 5 seconds.
    \endlist

    Video supports un-transformed, stretched, and uniformly scaled
    video presentation. For a description of stretched uniformly scaled
    presentation, see the \l fillMode property description.

    \sa MediaPlayer, VideoOutput

\omit
    \section1 Screen Saver

    If it is likely that an application will be playing video for an extended
    period of time without user interaction, it may be necessary to disable
    the platform's screen saver. The \l ScreenSaver (from \l QtSystemInfo)
    may be used to disable the screensaver in this fashion:

    \qml
    import QtSystemInfo 5.0

    ScreenSaver { screenSaverEnabled: false }
    \endqml
\endomit
*/

// TODO: Restore Qt System Info docs when the module is released

Item {
    id: video
    implicitWidth: videoOut.implicitWidth
    implicitHeight: videoOut.implicitHeight

    /*** Properties of VideoOutput ***/
    /*!
        \qmlproperty enumeration Video::fillMode

        Set this property to define how the video is scaled to fit the target
        area.

        \list
        \li VideoOutput.Stretch - the video is scaled to fit
        \li VideoOutput.PreserveAspectFit - the video is scaled uniformly to fit without
            cropping
        \li VideoOutput.PreserveAspectCrop - the video is scaled uniformly to fill, cropping
            if necessary
        \endlist

        Because this type is for convenience in QML, it does not
        support enumerations directly, so enumerations from \c VideoOutput are
        used to access the available fill modes.

        The default fill mode is preserveAspectFit.
    */
    property alias fillMode:            videoOut.fillMode

    /*!
        \qmlproperty enumeration Video::endOfStreamPolicy
        \since 6.9

        This property specifies the policy to apply when the video stream ends.

        The \c endOfStreamPolicy can be one of:

        \value ClearOutput      The video output is cleared.
        \value KeepLastFrame    The video output continues displaying the last
                                frame. Use the method \l clearOutput() to
                                clear the output manually.

        The default value is \c VideoOutput.ClearOutput.
    */
    property alias endOfStreamPolicy:            videoOut.endOfStreamPolicy

    /*!
        \qmlproperty int Video::orientation
        \since 6.9

        This property determines the angle, in degrees, at which the displayed video
        is rotated clockwise in video coordinates, where the Y-axis points
        downwards on the display.
        The orientation transformation is applied before \l mirrored.

        Only multiples of \c 90 degrees are supported, that is 0, 90, -90, 180, 270, etc.,
        otherwise, the specified value is ignored.

        The default value is \c 0.
    */
    property alias orientation:         videoOut.orientation


    /*!
        \qmlproperty int Video::mirrored

        Determines whether the displayed video is mirrored around its vertical axis.
        The mirroring is applied after \l orientation.
        The default value is \c false.
    */
    property alias mirrored:         videoOut.mirrored


    /*** Properties of MediaPlayer ***/

    /*!
        \qmlproperty enumeration Video::playbackState

        This read only property indicates the playback state of the media.

        \list
        \li MediaPlayer.PlayingState - the media is playing
        \li MediaPlayer.PausedState - the media is paused
        \li MediaPlayer.StoppedState - the media is stopped
        \endlist

        The default state is MediaPlayer.StoppedState.
    */
    property alias playbackState:        player.playbackState

    /*!
        \qmlproperty real Video::bufferProgress

        This property holds how much of the data buffer is currently filled,
        from 0.0 (empty) to 1.0
        (full).
    */
    property alias bufferProgress:  player.bufferProgress

    /*!
        \qmlproperty int Video::duration

        This property holds the duration of the media in milliseconds.

        If the media doesn't have a fixed duration (a live stream for example)
        this will be 0.
    */
    property alias duration:        player.duration

    /*!
        \qmlproperty int Video::loops

        Determines how often the media is played before stopping.
        Set to MediaPlayer.Infinite to loop the current media file forever.

        The default value is \c 1. Setting this property to \c 0 has no effect.
    */
    property alias loops:        player.loops

    /*!
        \qmlproperty enumeration Video::error

        This property holds the error state of the video.  It can be one of:

        \list
        \li MediaPlayer.NoError - there is no current error.
        \li MediaPlayer.ResourceError - the video cannot be played due to a problem
            allocating resources.
        \li MediaPlayer.FormatError - the video format is not supported.
        \li MediaPlayer.NetworkError - the video cannot be played due to network issues.
        \li MediaPlayer.AccessDenied - the video cannot be played due to insufficient
            permissions.
        \li MediaPlayer.ServiceMissing -  the video cannot be played because the media
            service could not be
        instantiated.
        \endlist
    */
    property alias error:           player.error

    /*!
        \qmlproperty string Video::errorString

        This property holds a string describing the current error condition in more detail.
    */
    property alias errorString:     player.errorString

    /*!
        \qmlproperty bool Video::hasAudio

        This property holds whether the current media has audio content.
    */
    property alias hasAudio:        player.hasAudio

    /*!
        \qmlproperty bool Video::hasVideo

        This property holds whether the current media has video content.
    */
    property alias hasVideo:        player.hasVideo

    /*!
        \qmlproperty mediaMetaData Video::metaData

        This property holds the meta data for the current media.

        See \l{MediaPlayer::metaData}{MediaPlayer.metaData} for details about each meta data key.

        \sa {mediaMetaData}
    */
    property alias metaData:        player.metaData

    /*!
        \qmlproperty bool Video::muted

        This property holds whether the audio output is muted.
    */
    property alias muted:           audioOutput.muted

    /*!
        \qmlproperty real Video::playbackRate

        This property holds the rate at which video is played at as a multiple
        of the normal rate.
    */
    property alias playbackRate:    player.playbackRate

    /*!
        \qmlproperty int Video::position

        This property holds the current playback position in milliseconds.
    */
    property alias position:        player.position

    /*!
        \qmlproperty bool Video::seekable

        This property holds whether the playback position of the video can be
        changed.

        If true, calling the \l seek() method or changing the \l position property
        will cause playback to seek to the new position.
    */
    property alias seekable:        player.seekable

    /*!
        \qmlproperty url Video::source

        This property holds the source URL of the media.
    */
    property alias source:          player.source

    /*!
        \since 6.7
        \qmlproperty bool Video::autoPlay

        This property controls whether the media begins to play automatically after it gets loaded.
        Defaults to \c false.
    */
    property alias autoPlay:        player.autoPlay

    /*!
        \qmlproperty real Video::volume

        This property holds the audio volume.

        The volume is scaled linearly from \c 0.0 (silence) to \c 1.0
        (full volume). Values outside this range will be clamped.

        The default volume is \c 1.0.

        UI volume controls should usually be scaled nonlinearly. For example,
        using a logarithmic scale will produce linear changes in perceived
        loudness, which is what a user would normally expect from a volume
        control. See \l {QtAudio::convertVolume()} for more details.
    */
    property alias volume:          audioOutput.volume

    /*!
        \qmlsignal Video::paused()

        This signal is emitted when playback is paused.
    */
    signal paused

    /*!
        \qmlsignal Video::stopped()

        This signal is emitted when playback is stopped.
    */
    signal stopped

    /*!
        \qmlsignal Video::playing()

        This signal is emitted when playback is started or continued.
    */
    signal playing

    /*!
        \qmlsignal Video::errorOccurred(error, errorString)

        This signal is emitted when an \a error has occurred. The \a errorString
        parameter may contain more detailed information about the error.
    */
    signal errorOccurred(int error, string errorString)

    VideoOutput {
        id: videoOut
        anchors.fill: video
    }

    MediaPlayer {
        id: player
        onPlaybackStateChanged: function(newState) {
            if (newState === MediaPlayer.PausedState)
                video.paused();
            else if (newState === MediaPlayer.StoppedState)
                video.stopped();
            else
                video.playing();
        }
        onErrorOccurred: function(error, errorString) {
            video.errorOccurred(error, errorString);
        }
        videoOutput: videoOut
        audioOutput: AudioOutput {
            id: audioOutput
        }
    }

    /*!
        \qmlmethod Video::play()

        Starts playback of the media.
    */
    function play() {
        player.play();
    }

    /*!
        \qmlmethod Video::pause()

        Pauses playback of the media.
    */
    function pause() {
        player.pause();
    }

    /*!
        \qmlmethod Video::stop()

        Stops playback of the media.
    */
    function stop() {
        player.stop();
    }

    /*!
        \qmlmethod Video::seek(offset)

        If the \l seekable property is true, seeks the current
        playback position to \a offset.

        \sa seekable, position
    */
    function seek(offset) {
        player.position = offset;
    }

    /*!
        \qmlmethod Video::clearOutput()
        \since 6.9

        Clears the video output by removing the current video frame.
        This method is recommended when you need to remove the last video frame after
        the video stream ends with the \l endOfStreamPolicy Video property
        set to \c KeepLastFrame.
    */
    function clearOutput() {
        videoOut.clearOutput();
    }
}
