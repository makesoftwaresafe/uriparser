/*
 * uriparser - RFC 3986 URI parsing library
 *
 * Copyright (C) 2014, Sebastian Pipping <sebastian@pipping.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <gtest/gtest.h>

#include <cstdio>

#include "UriConfig.h"  // for PACKAGE_VERSION
#include <uriparser/Uri.h>

TEST(VersionSuite, EnsureVersionDefinesInSync) {
    char INSIDE_VERSION[256];
    const int bytes_printed =
        sprintf(INSIDE_VERSION, "%d.%d.%d%s", URI_VER_MAJOR, URI_VER_MINOR,
                URI_VER_RELEASE, URI_VER_SUFFIX_ANSI);
    ASSERT_NE(bytes_printed, -1);
    EXPECT_STREQ(INSIDE_VERSION, PACKAGE_VERSION);
}

TEST(VersionSuite, EnsureRuntimeVersionAsExpected) {
    // NOTE: This needs a bump for every release
    EXPECT_STREQ(uriBaseRuntimeVersionA(), "0.9.9");
    EXPECT_STREQ(uriBaseRuntimeVersionW(), L"0.9.9");
}
