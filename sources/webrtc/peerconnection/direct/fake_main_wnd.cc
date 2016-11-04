#include "talk/examples/peerconnection/direct/fake_main_wnd.h"

#include "talk/examples/peerconnection/direct/defaults.h"
#include "webrtc/base/common.h"
#include "webrtc/base/logging.h"
#include "webrtc/base/stringutils.h"

#define DUMP_RAW_VIDEO 1

using rtc::sprintfn;

namespace {

FakeWidget *kFakeWidget = reinterpret_cast<FakeWidget *>(0xffffffff);

}

FakeMainWnd::FakeMainWnd(const char *server, int port) 
    : window_(NULL), vbox_(NULL), peer_list_(NULL),
      server_(server), callback_(NULL),
			rec_file_(*webrtc::FileWrapper::Create()) {
  char buffer[10];
  sprintfn(buffer, sizeof(buffer), "%i", port);
  port_ = buffer;

#if defined(DUMP_RAW_VIDEO) && (DUMP_RAW_VIDEO != 0)
	// Format is YUV I420.
	rec_file_.OpenFile("./webrtc.yuv", false, false, false);
#endif
}

FakeMainWnd::~FakeMainWnd() {
	if (rec_file_.Open()) {
		rec_file_.Flush();
		rec_file_.CloseFile();
	}
	delete &rec_file_;
}

void FakeMainWnd::RegisterObserver(MainWndCallback *callback) {
  callback_ = callback;
}

bool FakeMainWnd::IsWindow() {
  return window_ == kFakeWidget;
}

void FakeMainWnd::QueueUIThreadCallback(int msg_id, void *data) {
  callback_->UIThreadCallback(msg_id, data);
}

bool FakeMainWnd::Create() {
  ASSERT(window_ == NULL);
  // Set to non-null to indicate the window is created.
  window_ = kFakeWidget;
  SwitchToConnectUI();
  return window_ != NULL;
}

bool FakeMainWnd::Destroy() {
  if (!IsWindow())
    return false;

  callback_->Close();
  window_ = NULL;
  return true;
}

void FakeMainWnd::SwitchToConnectUI() {
  ASSERT(IsWindow());
  ASSERT(vbox_ == NULL);

  peer_list_ = NULL;
  vbox_ = kFakeWidget;

  // Simulate to press |connect| button, then |OnClicked| will be called.
  OnClicked();
}

void FakeMainWnd::SwitchToPeerList(const Peers &peers) {
  if (!peer_list_) {
    vbox_ = NULL;
    peer_list_ = kFakeWidget;
  }

  LOG(INFO) << "=== List of currently connected peers ===";
  for (Peers::const_iterator i = peers.begin(); i != peers.end(); ++i)
    LOG(INFO) << "*" << i->first << "* -- " << i->second;

  if (peers.begin() != peers.end()) {
    // Connect to the first peer in the list.
    int id = peers.begin()->first;
    if (id != -1)
      OnRowActivated(1, id);
  }
}

void FakeMainWnd::SwitchToStreamingUI() {
  peer_list_ = NULL;
}

MainWindow::UI FakeMainWnd::current_ui() {
  if (vbox_)
    return CONNECT_TO_SERVER;

  if (peer_list_)
    return LIST_PEERS;

  return STREAMING;
}

void FakeMainWnd::StartLocalRenderer(webrtc::VideoTrackInterface *local_video) {
  RTC_UNUSED(local_video);
}

void FakeMainWnd::StopLocalRenderer() {
}

void FakeMainWnd::StartRemoteRenderer(webrtc::VideoTrackInterface *remote_video) {
  remote_renderer_.reset(new VideoRenderer(this, remote_video));
}

void FakeMainWnd::StopRemoteRenderer() {
  remote_renderer_.reset();
}

void FakeMainWnd::MessageBox(const char *caption, const char *text,
                             bool is_error) {
  LOG(LERROR) << "*** " << caption << " ***\n"
              << text;
}

void FakeMainWnd::OnClicked() {
  callback_->StartLogin(server_, atoi(port_.c_str()));
}

void FakeMainWnd::OnRowActivated(int row_index, int peer_id) {
  callback_->ConnectToPeer(peer_id);
}

void FakeMainWnd::OnRedraw() {
	{
	rtc::CritScope cs(&crit_);

	VideoRenderer *remote_renderer = remote_renderer_.get();
	if (remote_renderer && remote_renderer->image() != NULL) {
#if defined(DUMP_RAW_VIDEO) && (DUMP_RAW_VIDEO != 0)
		if (rec_file_.Open()) {
			int width = remote_renderer->width();
			int height = remote_renderer->height();

			rec_file_.Write(remote_renderer->image(), width * height * 3 / 2);
		}
#endif
	}
	}
}

FakeMainWnd::VideoRenderer::VideoRenderer(
    FakeMainWnd *main_wnd,
    webrtc::VideoTrackInterface *track_to_render)
    : width_(0),
      height_(0),
      main_wnd_(main_wnd),
      rendered_track_(track_to_render) {
  rendered_track_->AddRenderer(this);
}

FakeMainWnd::VideoRenderer::~VideoRenderer() {
  rendered_track_->RemoveRenderer(this);
}

void FakeMainWnd::VideoRenderer::SetSize(int width, int height) {
  rtc::CritScope cs(&main_wnd_->crit_);

  if (width_ == width && height_ == height)
    return;

  width_ = width;
  height_ = height;
  image_.reset(new uint8[width * height * 3 / 2]);
}

void FakeMainWnd::VideoRenderer::RenderFrame(
    const cricket::VideoFrame* video_frame) {
  {
  rtc::CritScope cs(&main_wnd_->crit_);

  const cricket::VideoFrame* frame = video_frame->GetCopyWithRotationApplied();

  SetSize(static_cast<int>(frame->GetWidth()),
          static_cast<int>(frame->GetHeight()));

	memcpy(image_.get(),
			   frame->GetYPlane(), frame->GetYPitch() * frame->GetHeight());
	memcpy(image_.get() + frame->GetYPitch() * frame->GetHeight(),
			   frame->GetUPlane(), frame->GetUPitch() * frame->GetHeight() / 2);
	memcpy(image_.get() + frame->GetYPitch() * frame->GetHeight() + frame->GetUPitch() * frame->GetHeight() / 2,
			   frame->GetVPlane(), frame->GetVPitch() * frame->GetHeight() / 2);
  }

  // Should call OnRedraw in a new thread.
  main_wnd_->OnRedraw();
}
