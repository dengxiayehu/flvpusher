#ifndef PEERCONNECTION_SAMPLES_DIRECT_FAKE_MAIN_WND_H_
#define PEERCONNECTION_SAMPLES_DIRECT_FAKE_MAIN_WND_H_
#pragma

#include <string>

#include "talk/app/webrtc/mediastreaminterface.h"
#include "talk/examples/peerconnection/direct/peer_connection_client.h"
#include "talk/media/base/mediachannel.h"
#include "talk/media/base/videocommon.h"
#include "talk/media/base/videoframe.h"
#include "webrtc/system_wrappers/interface/file_wrapper.h"

class MainWndCallback {
public:
  virtual void StartLogin(const std::string &server, int port) = 0;
  virtual void DisconnectFromServer() = 0;
  virtual void ConnectToPeer(int peer_id) = 0;
  virtual void DisconnectFromCurrentPeer() = 0;
  virtual void UIThreadCallback(int msg_id, void *data) = 0;
  virtual void Close() = 0;
protected:
  virtual ~MainWndCallback() {}
};

// Pure virtual interface for the main window.
class MainWindow {
public:
  virtual ~MainWindow() {}

  enum UI {
    CONNECT_TO_SERVER,
    LIST_PEERS,
    STREAMING,
  };

  virtual void RegisterObserver(MainWndCallback *callback) = 0;

  virtual bool IsWindow() = 0;
  virtual void MessageBox(const char *caption, const char *text,
                          bool is_error) = 0;

  virtual UI current_ui() = 0;

  virtual void SwitchToConnectUI() = 0;
  virtual void SwitchToPeerList(const Peers &peers) = 0;
  virtual void SwitchToStreamingUI() = 0;

  virtual void StartLocalRenderer(webrtc::VideoTrackInterface *local_video) = 0;
  virtual void StopLocalRenderer() = 0;
  virtual void StartRemoteRenderer(webrtc::VideoTrackInterface *remote_video) = 0;
  virtual void StopRemoteRenderer() = 0;

  virtual void QueueUIThreadCallback(int msg_id, void *data) = 0;
};

typedef void FakeWidget;

class FakeMainWnd : public MainWindow {
public:
  FakeMainWnd(const char *server, int port);
  ~FakeMainWnd();

  virtual void RegisterObserver(MainWndCallback *callback);
  virtual bool IsWindow();
  virtual void SwitchToConnectUI();
  virtual void SwitchToPeerList(const Peers &peers);
  virtual void SwitchToStreamingUI();
  virtual void MessageBox(const char *caption, const char *text,
                          bool is_error);
  virtual MainWindow::UI current_ui();
  virtual void StartLocalRenderer(webrtc::VideoTrackInterface *local_video);
  virtual void StopLocalRenderer();
  virtual void StartRemoteRenderer(webrtc::VideoTrackInterface *remote_video);
  virtual void StopRemoteRenderer();

  virtual void QueueUIThreadCallback(int msg_id, void *data);

  // Creates and shows the main window with the |Connect UI| enabled.
  bool Create();

  // Destroys the window. When the window is destroyed, it ends the
  // main message loop.
  bool Destroy();

  // Callback for when the user clicks the "Connect" button.
  void OnClicked();

  // Callback when the user double clicks a peer in order to initiate a
  // connection.
  void OnRowActivated(int row_index, int peer_id);

  void OnRedraw();

protected:
  class VideoRenderer : public webrtc::VideoRendererInterface {
  public:
    VideoRenderer(FakeMainWnd *main_wnd,
                  webrtc::VideoTrackInterface *track_to_render);
    virtual ~VideoRenderer();

    // VideoRendererInterface implementation
    virtual void SetSize(int width, int height) override;
    virtual void RenderFrame(const cricket::VideoFrame *frame) override;

    const uint8* image() const {
      return image_.get();
    }

    int width() const {
      return width_;
    } 

    int height() const {
      return height_;
    }

  protected:
    rtc::scoped_ptr<uint8[]> image_;
    int width_;
    int height_;
    FakeMainWnd* main_wnd_;
    rtc::scoped_refptr<webrtc::VideoTrackInterface> rendered_track_;
  };

protected:
  MainWndCallback *callback_;
  FakeWidget *window_;
  FakeWidget *vbox_;
  FakeWidget *peer_list_;
  std::string server_;
  std::string port_;
  mutable rtc::CriticalSection crit_;
  rtc::scoped_ptr<VideoRenderer> remote_renderer_;

	webrtc::FileWrapper& rec_file_;
};

#endif // PEERCONNECTION_SAMPLES_DIRECT_FAKE_MAIN_WND_H_
