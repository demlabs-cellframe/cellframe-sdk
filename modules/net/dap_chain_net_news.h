/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2020
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

 DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 DAP is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "dap_http.h"

/* Set news in the selected language
 * a_lang - a language like "en", "ru", "fr"
 * a_data_news - news data
 * a_data_news_len length of news
 */
int dap_chain_net_news_write(const char *a_lang, char *a_data_news, size_t a_data_news_len);

/* Get news in the selected language
 * a_lang - a language like "en", "ru", "fr"
 */
byte_t* dap_chain_net_news_read(const char *a_lang, size_t *a_news_len);

void dap_chain_net_news_add_proc(struct dap_http * sh);
