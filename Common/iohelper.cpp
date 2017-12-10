#pragma once
#include "iohelper.h"

namespace MyProxy {
	template <>
	static DataVec IoHelper::parseType<DataVec>(size_t size) {
		return DataVec(size);
	}
	template<>
	void IoHelper::write<std::vector<char>>(const std::vector<char> & value, size_t)
	{
		ios.write(value.data(), value.size());
	}
	template<>
	void IoHelper::read<std::vector<char>>(std::vector<char> & value, size_t bytes)
	{
		ios.read(value.data(), value.size());
	}
	template <>
	std::vector<char> IoHelper::getValue<std::vector<char>>(size_t count) {
		std::vector<char> value(count);
		read(value);
		return value;
	}
}