#include "local.h"
#include "server.h"

auto opensslLogger = spdlog::stdout_color_mt("OPENSSL");

std::vector<std::shared_ptr<std::mutex>> locks;

#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_0_0  
void ssl_threadid_function(CRYPTO_THREADID * id) {
	auto this_id = std::hash<std::thread::id>{}(std::this_thread::get_id());
	CRYPTO_THREADID_set_numeric(id, this_id);
}
#else  
unsigned long ssl_threadid_function_deprecated() {
	return std::hash<std::thread::id>{}(std::this_thread::get_id());
}
#endif  

void ssl_locking_callback(int mode, int type, const char *file, int line) {
	if (mode & CRYPTO_LOCK) {
		//opensslLogger->trace("SSL lock");
		locks[type]->lock();
	}
	else {
		//opensslLogger->trace("SSL unlock");
		locks[type]->unlock();
	}
}

void ssl_thread_setup() {
	auto size = CRYPTO_num_locks();
	for (size_t i = 0; i < size; i++) {
		locks.push_back(std::make_shared<std::mutex>());
	}
#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_0_0  
	CRYPTO_THREADID_set_callback(ssl_threadid_function);
#else  
	CRYPTO_set_id_callback(ssl_threadid_function_deprecated);
#endif  
	CRYPTO_set_locking_callback(ssl_locking_callback);
}

void ssl_thread_cleanup() {
	CRYPTO_set_locking_callback(NULL);
	locks.clear();
}

int main() {

	using namespace std;

	ssl_thread_setup();

	//spd::set_async_mode(4096);
	spdlog::set_pattern("[%D %H:%M:%e] [%L] [%t] [%n]\t%v");
	spdlog::set_level(spdlog::level::debug);
	//auto f = std::make_shared<spdlog::pattern_formatter>("[%D %H:%M:%e]\t[%L]\t[%n]\t%v");
	//spdlog::set_formatter(f);

	boost::asio::io_service io;

	MyProxy::Local::Proxy local(io);
	local.bind("1083");
	local.setServer("localhost", "1084");
	local.start();

	MyProxy::Server::Server server(io);
	server.bind("1084");
	server.setCert("E:\\pki\\servercert.pem");
	server.setKey("E:\\pki\\serverkey.pem");
	server.start();

	//io.run();

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

	ssl_thread_cleanup();

	::system("pause");

	return 0;

}