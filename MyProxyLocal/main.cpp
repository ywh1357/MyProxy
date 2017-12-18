#include "local.h"
#include "sslsetting.h"

int main() {

	using namespace std;

	MyProxy::openssl_config::thread_setup();	

	//spd::set_async_mode(4096);
	spdlog::set_pattern("[%D %H:%M:%e] [%L] [%t] [%n]\t%v");
	spdlog::set_level(spdlog::level::debug);
	//auto f = std::make_shared<spdlog::pattern_formatter>("[%D %H:%M:%e]\t[%L]\t[%n]\t%v");
	//spdlog::set_formatter(f);

	boost::asio::io_service io;

	MyProxy::Local::Local local(io);
	local.bind("1083","127.0.0.1");
	local.setServer("127.0.0.1", "1084");
	local.setCertAndKey("E:\\pki\\clientcert.pem", "E:\\pki\\clientkey.pkcs8.pem");
	local.start();

	auto threadLogger = spdlog::stdout_logger_mt("IO Thread");
	threadLogger->set_pattern("[%D %H:%M:%e] [%L] [%t] [%n]\t%v");
	threadLogger->set_level(spdlog::level::debug);

	std::vector<std::thread> threads;
	for (size_t i = 0; i < std::thread::hardware_concurrency(); i++) {
		threads.push_back(std::thread([&io, threadLogger] {
			spdlog::get("IO Thread")->info("Io service running!");
			try {
				io.run();
			}
			catch (std::exception ex) {
				spdlog::get("IO Thread")->error("Catch exception: ",ex.what());
				throw;
			}
		}));
	}

	for (auto &t : threads) {
		t.join();
	}

	MyProxy::openssl_config::thread_cleanup();

	::system("pause");

	return 0;

}