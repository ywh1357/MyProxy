#pragma once

namespace MyProxy {

	class openssl_config {
	public:
		static void thread_setup();
		static void thread_cleanup();
	};

}