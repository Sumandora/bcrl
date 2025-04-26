#ifndef BCRL_LAMBDAINSERTER_HPP
#define BCRL_LAMBDAINSERTER_HPP

#include <cstddef>
#include <utility>

namespace BCRL::detail {
	template <typename F>
	class LambdaInserter {
		F callback;

	public:
		// NOLINTNEXTLINE(readability-identifier-naming)
		using difference_type = std::ptrdiff_t;

		constexpr explicit LambdaInserter(F&& callback)
			: callback(std::move(callback))
		{
		}

		constexpr LambdaInserter& operator=(auto&& element)
		{
			callback(element);
			return *this;
		}

		constexpr LambdaInserter& operator*()
		{
			return *this;
		}

		constexpr LambdaInserter& operator++()
		{
			return *this;
		}

		constexpr LambdaInserter& operator++(int)
		{
			return *this;
		}
	};
}

#endif
