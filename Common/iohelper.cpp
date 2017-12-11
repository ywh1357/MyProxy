#include "iohelper.h"

namespace MyProxy {

	DataVecBuf::DataVecBuf(DataVec & vec) :
		vec(vec),
		_first(vec.data()),
		_last(vec.data() + vec.size()) {
	}

	DataVecBuf::int_type DataVecBuf::overflow(int_type ch)
	{
		vec.push_back(ch);
		return traits_type::not_eof(ch);
	}

	DataVecBuf::int_type DataVecBuf::underflow()
	{
		return (_gpos == vec.size() ? traits_type::eof() : traits_type::to_int_type(vec[_gpos]));
	}

	DataVecBuf::int_type DataVecBuf::uflow()
	{
		return (_gpos == vec.size() ? traits_type::eof() : traits_type::to_int_type(vec[_gpos++]));
	}

	std::streamsize DataVecBuf::showmanyc()
	{
		return vec.size() - _gpos;
	}

	std::streamsize DataVecBuf::xsputn(const char * s, std::streamsize count)
	{
		vec.reserve(vec.size() + count);
		auto iter = std::copy_n(s, count, std::back_inserter(vec));
		return count;
	}

	std::streamsize DataVecBuf::xsgetn(char * s, std::streamsize count)
	{
		auto available = std::min(count, static_cast<std::streamsize>(vec.size() - _gpos));
		if (available > 0) {
			std::memcpy(s, vec.data() + _gpos, available);
			_gpos += available;
		}
		return available;
	}

	template <>
	DataVec IoHelper::parseType<DataVec>(size_t size) {
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