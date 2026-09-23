/*! \file
 *  \brief Test support: an input placed against a PAGE_NOACCESS page.
 *
 *  WHY. A parser that reads past its input does not crash on its own: it reads
 *  whatever memory follows, and publishes it in a perfectly valid JSON. The
 *  input is therefore copied so that it touches a page mapped PAGE_NOACCESS —
 *  a single byte read beyond it raises an access violation.
 *
 *  BOTH SIDES. A copy that ENDS at the guard page catches reads past the end;
 *  one that STARTS right after a guard page catches reads before the start — a
 *  negative offset computed from the data, which the first layout lets through
 *  because the bytes before the input are mapped. The test harnesses run every
 *  input both ways.
 *
 *  Used by lnk_test.cpp and parsers_test.cpp only: never compiled into WAC.
 */
#pragma once
#include <windows.h>
#include <cstring>
#include <vector>

/*! Which end of the input touches the guard page. */
enum class GuardSide {
	After,   //!< the input ends at the guard page: reads past the end fault
	Before   //!< the input starts right after the guard page: reads before it fault
};

/*! A copy of an input placed against a PAGE_NOACCESS page, released on scope exit. */
class GuardedCopy {
public:
	/*! Copies `input` against a guard page.
	 *  @param input the bytes to place
	 *  @param side which end touches the guard page */
	GuardedCopy(const std::vector<BYTE>& input, GuardSide side) : size_(input.size()) {
		SYSTEM_INFO si;
		GetSystemInfo(&si);
		const size_t page = si.dwPageSize;
		const size_t dataPages = (size_ + page - 1) / page + 1;
		base_ = static_cast<BYTE*>(VirtualAlloc(nullptr, (dataPages + 1) * page,
		                                        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
		if (base_ == nullptr) return;
		DWORD old = 0;
		if (side == GuardSide::After) {
			VirtualProtect(base_ + dataPages * page, page, PAGE_NOACCESS, &old);
			data_ = base_ + dataPages * page - size_;
		}
		else {
			VirtualProtect(base_, page, PAGE_NOACCESS, &old);
			data_ = base_ + page;
		}
		if (size_) std::memcpy(data_, input.data(), size_);
	}

	//! Releases the pages.
	~GuardedCopy() { if (base_) VirtualFree(base_, 0, MEM_RELEASE); }

	GuardedCopy(const GuardedCopy&) = delete;             //!< one owner of the pages
	GuardedCopy& operator=(const GuardedCopy&) = delete;  //!< one owner of the pages

	/*! @return the placed copy, or nullptr if the allocation failed */
	BYTE* data() const { return data_; }
	/*! @return the number of bytes of the input */
	size_t size() const { return size_; }

private:
	BYTE* base_ = nullptr;   //!< the whole allocation
	BYTE* data_ = nullptr;   //!< the copy, against the guard page
	size_t size_ = 0;        //!< size of the input
};
