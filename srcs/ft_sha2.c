/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_sha2.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vgladush <vgladush@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/08/18 20:26:41 by vgladush          #+#    #+#             */
/*   Updated: 2018/09/22 16:19:42 by vgladush         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/ft_ssl.h"

static const uint32_t	g_t[LEN] = {0x428A2F98, 0x71374491, 0xB5C0FBCF,
	0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5, 0xD807AA98,
	0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7,
	0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F,
	0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D, 0xB00327C8,
	0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967, 0x27B70A85,
	0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E,
	0x92722C85, 0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819,
	0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116, 0x1E376C08, 0x2748774C,
	0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3, 0x748F82EE,
	0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7,
	0xC67178F2};

static void				ft_hashing(t_ssl *ssl, t_32x *sh, uint32_t i, uint32_t j)
{
	while (++i < TW)
		sh->inter[i] = sh->oth[i];
	while (1)
	{
		sh->inter[8] = SIGM(sh->inter[A], 2, 13, 22, 32) +
			((sh->inter[A] & sh->inter[B]) ^ (sh->inter[A] &
			sh->inter[C]) ^ (sh->inter[B] & sh->inter[C]));
		sh->inter[9] = SIGM(sh->inter[E], 6, 11, 25, 32) +
			((sh->inter[E] & sh->inter[F]) ^ ((~ sh->inter[E]) &
			sh->inter[G])) + g_t[j % LEN] + sh->inter[H] + sh->words[j % LEN];
		sh->inter[H] = sh->inter[G];
		sh->inter[G] = sh->inter[F];
		sh->inter[F] = sh->inter[E];
		sh->inter[E] = sh->inter[D] + sh->inter[9];
		sh->inter[D] = sh->inter[C];
		sh->inter[C] = sh->inter[B];
		sh->inter[B] = sh->inter[A];
		sh->inter[A] = sh->inter[8] + sh->inter[9];
		ft_debug(ssl, sh, j + 1, LEN);
		if (!(++j % LEN))
			break ;
	}
	j = -1;
	while (++j < TW)
		sh->oth[j] += sh->inter[j];
}

static void				ft_hash(t_ssl *ssl, t_32x *sh, uint32_t i, uint32_t j)
{
	while (i < ssl->sze + ssl->size)
	{
		j = -1;
		while (++j < WS)
			sh->words[j] = 0;
		j = 0;
		while (j < WS)
		{
			if (i < ssl->size)
				sh->words[j] += (uint32_t)ssl->stream[i] << ((3 - i % 4) * 8);
			else
				sh->words[j] += (uint32_t)ssl->end[i - ssl->size]
			<< ((3 - i % 4) * 8);
			j = (!(++i % 4) ? j + 1 : j);
		}
		while (j < LEN)
		{
			sh->words[j] = DELT(sh->words[j - 15], 7, 18, 3, 32) +
			sh->words[j - 16] + sh->words[j - 7] +
			DELT(sh->words[j - 2], 17, 19, 10, 32);
			j++;
		}
		ft_hashing(ssl, sh, -1, i - LEN);
	}
}

static void				out_res(t_ssl *ssl, t_32x *sh)
{
	char				*s;
	int					t;
	int					i;
	int					j;

	i = 0;
	t = (ssl->type[0] == SHA_224 ? 6 : 7);
	j = (ssl->type[0] == SHA_224 ? 28 : 32);
	ssl->res = ft_strnew(0);
	while (i < j)
	{
		s = ft_itoabase((unsigned char)sh->oth[t], WS, 'a');
		sh->oth[t] = sh->oth[t] >> 8;
		if (ft_strlen(s) < 2)
			s = ft_joinfree("0", s, 2);
		ssl->res = ft_joinfree(s, ssl->res, 3);
		++i;
		if (i < j && ssl->flg[CF])
			ssl->res = ft_joinfree(":", ssl->res, 2);
		if (!(i % 4))
			t--;
	}
}

void					ft_sha2(t_ssl *ssl)
{
	t_32x				sh;
	size_t				tm;
	size_t				i;

	tm = ssl->size;
	ssl->sze = (tm % LEN > 55 ? (LEN - tm % LEN) + LEN : LEN - tm % LEN);
	ssl->end = (unsigned char *)ft_strnew(ssl->sze);
	ssl->end[0] = 0x80;
	i = ssl->sze;
	tm *= 8;
	while (--i > ssl->sze - 9)
	{
		ssl->end[i] = tm;
		tm = tm >> 8;
	}
	sh.oth[A] = (ssl->type[0] == SHA_224 ? 0xc1059ed8 : 0x6A09E667);
	sh.oth[B] = (ssl->type[0] == SHA_224 ? 0x367cd507 : 0xBB67AE85);
	sh.oth[C] = (ssl->type[0] == SHA_224 ? 0x3070dd17 : 0x3C6EF372);
	sh.oth[D] = (ssl->type[0] == SHA_224 ? 0xf70e5939 : 0xA54FF53A);
	sh.oth[E] = (ssl->type[0] == SHA_224 ? 0xffc00b31 : 0x510E527F);
	sh.oth[F] = (ssl->type[0] == SHA_224 ? 0x68581511 : 0x9B05688C);
	sh.oth[G] = (ssl->type[0] == SHA_224 ? 0x64f98fa7 : 0x1F83D9AB);
	sh.oth[H] = (ssl->type[0] == SHA_224 ? 0xbefa4fa4 : 0x5BE0CD19);
	ft_hash(ssl, &sh, 0, 0);
	out_res(ssl, &sh);
}
