/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_md5.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vgladush <vgladush@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/08/18 20:26:41 by vgladush          #+#    #+#             */
/*   Updated: 2018/09/08 20:12:30 by vgladush         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/ft_ssl.h"

static const int		g_s[LEN] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17,
	22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

static const uint32_t	g_k[LEN] = {0xd76aa478, 0xe8c7b756, 0x242070db,
	0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8,
	0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e,
	0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
	0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87,
	0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942,
	0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60,
	0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039,
	0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7,
	0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 0x6fa87e4f,
	0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
	0xeb86d391};

static uint32_t			md5_func(t_32x *md, uint32_t i)
{
	if (i < WS)
		return ((md->inter[B] & md->inter[C]) |
			((~md->inter[B]) & md->inter[D]));
	if (i < 32)
		return ((md->inter[B] & md->inter[D]) |
			(md->inter[C] & (~md->inter[D])));
	if (i < 48)
		return (md->inter[B] ^ md->inter[C] ^ md->inter[D]);
	return (md->inter[C] ^ (md->inter[B] | (~md->inter[D])));
}

static void				ft_hashing(t_ssl *ssl, t_32x *md, int i, int j)
{
	while (1)
	{
		md->inter[A] = md->inter[B] + ROTL((md5_func(md, i % LEN)
			+ md->inter[A] + md->words[j] + g_k[i % LEN]), g_s[i % LEN], 32);
		md->inter[E] = md->inter[A];
		md->inter[A] = md->inter[D];
		md->inter[D] = md->inter[C];
		md->inter[C] = md->inter[B];
		md->inter[B] = md->inter[E];
		if (i % LEN < 15)
			j++;
		else if (i % LEN < 31)
			j = (i % LEN * 5 + 6) % WS;
		else if (i % LEN < 47)
			j = (i % LEN * 3 + 8) % WS;
		else
			j = (i % LEN * 7 + 7) % WS;
		ft_debug(ssl, md, i + 1, LEN);
		if (!(++i % LEN))
			break ;
	}
}

static void				ft_hash(t_ssl *ssl, t_32x *md, uint32_t i, int32_t j)
{
	while (i < ssl->sze + ssl->size)
	{
		j = -1;
		while (++j < WS)
			md->words[j] = 0;
		j = -1;
		while (++j < 4)
			md->inter[j] = md->oth[j];
		j = 0;
		while (j < WS)
		{
			if (i < ssl->size)
				md->words[j] += (uint32_t)ssl->stream[i] << (i % 4 * 8);
			else
				md->words[j] += ssl->end[i - ssl->size] << (i % 4 * 8);
			++i;
			j = (!(i % 4) ? j + 1 : j);
		}
		ft_hashing(ssl, md, i - LEN, 0);
		j = -1;
		while (++j < 4)
			md->oth[j] += md->inter[j];
	}
}

static void				out_res(t_ssl *ssl, t_32x *md)
{
	char				*s;
	int					t;
	int					i;

	i = 0;
	t = 0;
	ssl->res = ft_strnew(0);
	while (i < WS)
	{
		s = ft_itoabase((unsigned char)md->oth[t], WS, 'a');
		md->oth[t] = md->oth[t] >> 8;
		if (ft_strlen(s) < 2)
			s = ft_joinfree("0", s, 2);
		ssl->res = ft_joinfree(ssl->res, s, 3);
		++i;
		if (i < WS && ssl->flg[CF])
			ssl->res = ft_joinfree(ssl->res, ":", 1);
		if (!(i % 4))
			t++;
	}
}

void					ft_md5(t_ssl *ssl)
{
	t_32x				md;
	size_t				tm;
	size_t				i;

	tm = ssl->size;
	ssl->sze = (tm % LEN > 55 ? (LEN - tm % LEN) + LEN : LEN - tm % LEN);
	ssl->end = (unsigned char *)ft_strnew(ssl->sze);
	ssl->end[0] = 0x80;
	i = ssl->sze - 9;
	tm *= 8;
	while (++i < ssl->sze)
	{
		ssl->end[i] = tm;
		tm = tm >> 8;
	}
	md.oth[A] = 0x67452301;
	md.oth[B] = 0xefcdab89;
	md.oth[C] = 0x98badcfe;
	md.oth[D] = 0x10325476;
	ft_hash(ssl, &md, 0, 0);
	out_res(ssl, &md);
}
