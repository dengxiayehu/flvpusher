#include "talk/examples/peerconnection/direct/conductor.h"
#include "talk/examples/peerconnection/direct/flagdefs.h"
#include "talk/examples/peerconnection/direct/fake_main_wnd.h"
#include "talk/examples/peerconnection/direct/peer_connection_client.h"

#include "webrtc/base/ssladapter.h"
#include "webrtc/base/thread.h"

class CustomSocketServer : public rtc::PhysicalSocketServer {
public:
  CustomSocketServer(rtc::Thread *thread, FakeMainWnd *wnd)
      : thread_(thread), wnd_(wnd), conductor_(NULL), client_(NULL) {}
  virtual ~CustomSocketServer() {}

  void set_client(PeerConnectionClient *client) { client_ = client; }
  void set_conductor(Conductor *conductor) { conductor_ = conductor; }

  virtual bool Wait(int cms, bool process_io) override {
    if (!wnd_->IsWindow() &&
        conductor_ && !conductor_->connection_active() &&
        client_ != NULL && !client_->is_connected()) {
      thread_->Quit();
    }
    return rtc::PhysicalSocketServer::Wait(0, process_io);
  }

protected:
  rtc::Thread *thread_;
  FakeMainWnd *wnd_;
  Conductor *conductor_;
  PeerConnectionClient *client_;
};

#if 1
#include <signal.h>
#include <pthread.h>

class SignalProcessThread : public rtc::Thread {
public:
	SignalProcessThread(sigset_t *set, Thread *main_thread, FakeMainWnd *wnd)
		: set_(set), main_thread_(main_thread), wnd_(wnd) { }
	virtual ~SignalProcessThread() { }
	virtual void Run();

private:
	sigset_t *set_;
	Thread *main_thread_;
	FakeMainWnd *wnd_;
};

class FunctorQuit {
public:
	explicit FunctorQuit(FakeMainWnd *wnd) : wnd_(wnd) { }
	void operator()() { wnd_->Destroy(); }

private:
	FakeMainWnd *wnd_;
};

void SignalProcessThread::Run() {
	int ret, sig;

	for ( ; ; ) {
		ret = sigwait(set_, &sig);
		if (ret != 0) {
			fprintf(stderr, "sigwait failed: %s\n", strerror(ret));
			break;
		}

		if (sig == SIGINT) {
			printf("Program received signal SIGINT, quit ..\n");
			FunctorQuit f(wnd_);
			main_thread_->Invoke<void>(f);
			break;
		}
	}
}

int main(int argc, char* argv[]) {
  rtc::FlagList::SetFlagsFromCommandLine(&argc, argv, true);
  if (FLAG_help) {
    rtc::FlagList::Print(NULL, false);
    return 0;
  }

  // Abort if the user specifies a port that is outside the allowed
  // range [1, 65535].
  if ((FLAG_port < 1) || (FLAG_port > 65535)) {
    fprintf(stderr,
						"Error: %i is not a valid port.\n", FLAG_port);
    return -1;
  }

	int ret;
	sigset_t set;

	// Block SIGINT in main thread and its inheritors.
	sigaddset(&set, SIGINT);

	ret = pthread_sigmask(SIG_BLOCK, &set, NULL);
	if (ret != 0) {
		fprintf(stderr, "pthread_sigmask failed: %s\n", strerror(ret));
		return -1;
	}

  FakeMainWnd wnd(FLAG_server, FLAG_port);
	
  rtc::AutoThread auto_thread;
  rtc::Thread *thread = rtc::Thread::Current();
  CustomSocketServer socket_server(thread, &wnd);
  thread->set_socketserver(&socket_server);
	
	// Create a thread to handle the signals.
	SignalProcessThread spt(&set, thread, &wnd);
	spt.Start();
	
  rtc::InitializeSSL();
  // Must be constructed after we set the socketserver.
  PeerConnectionClient client;
  rtc::scoped_refptr<Conductor> conductor(
      new rtc::RefCountedObject<Conductor>(&client, &wnd));
  socket_server.set_client(&client);
  socket_server.set_conductor(conductor);

  // Must be called after the conductor is constructed.
  wnd.Create();

  thread->Run();

  wnd.Destroy();

  thread->set_socketserver(NULL);
  rtc::CleanupSSL();
  return 0;
}
#endif
