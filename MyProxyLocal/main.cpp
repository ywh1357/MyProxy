#include "local.h"
#include "argh.h"

int main(int argc,char* argv[]) {

	using namespace std;

	auto cmdl = argh::parser(argc, argv, argh::parser::NO_SPLIT_ON_EQUALSIGN | argh::parser::PREFER_PARAM_FOR_UNREG_OPTION);

	//spd::set_async_mode(4096);
	spdlog::set_pattern("[%D %H:%M:%e] [%L] [%t] [%n]\t%v");
	spdlog::level::level_enum level;
	level = cmdl[{"--debug"}] ? spdlog::level::debug : spdlog::level::info;
	spdlog::set_level(level);
	//auto f = std::make_shared<spdlog::pattern_formatter>("[%D %H:%M:%e]\t[%L]\t[%n]\t%v");
	//spdlog::set_formatter(f);

	boost::asio::io_service io;

	MyProxy::Local::Local local(io);

	std::string caPath;
	if (cmdl("--CA") >> caPath) {
		local.setCA(caPath);
	}

	std::string port, address;
	address = cmdl({ "--local-address" }, "127.0.0.1").str();
	port = cmdl({ "--local-port" }, "1080").str();
	local.bind(port, address);

	std::string serverHost, serverPort;
	serverHost = cmdl("--server-host").str();
	serverPort = cmdl("--server-port").str();
	local.setServer(serverHost, serverPort);
	
	std::string cert, key;
	bool hasCert = false, hasKey = false;
	if (cmdl("--cert") >> cert)
		hasCert = true;
	if (cmdl("--key") >> key)
		hasKey = true;
	if (hasCert && hasKey) {
		local.setCertAndKey(cert, key); //openssl pkcs8 -topk8 -in .\serverkey.pem -nocrypt -out serverkey.pkcs8.pem
	}
	else if (hasCert || hasKey) {
		std::cerr << "Please provide a certificate key pair\n";
		exit(1);
	}

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

	return 0;

}