/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_sha5.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vgladush <vgladush@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/08/18 20:26:41 by vgladush          #+#    #+#             */
/*   Updated: 2018/09/02 19:45:27 by vgladush         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/ft_ssl.h"

static const uint64_t	g_h[BLEN] = {0x428a2f98d728ae22, 0x7137449123ef65cd,
	0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
	0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c,
	0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1,
	0x9bdc06a725c71235, 0xc19bf174cf692694, 0xe49b69c19ef14ad2,
	0xEfbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4,
	0x76f988da831153b5, 0x983e5152ee66dfab, 0xa831c66d2db43210,
	0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2,
	0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
	0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8,
	0x81c2c92e47edaee6, 0x92722c851482353b, 0xa2bfe8a14cf10364,
	0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a,
	0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
	0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63,
	0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72,
	0x8cc702081a6439ec, 0x90befffa23631e28, 0xa4506cebde82bde9,
	0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
	0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae,
	0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493,
	0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c, 0x4cc5d4becb3e42b6,
	0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817};

static void		out_res(t_ssl *ssl, t_64x *sh, int i, int j)
{
	char		*s;
	int			t;

	t = 0;
	ssl->res = ft_strnew(0);
	if (ssl->type[0] < SHA_512_224)
		j = (ssl->type[0] == SHA_512 ? 64 : 48);
	else
		j = (ssl->type[0] == SHA_512_224 ? 28 : 32);
	while (i < j)
	{
		s = ft_itoabase((unsigned char)(sh->oth[t] >>
			((7 - i % 8) * 8)), WS, 'a');
		if (ft_strlen(s) < 2)
			s = ft_joinfree("0", s, 2);
		ssl->res = ft_joinfree(ssl->res, s, 3);
		++i;
		if (i < j && ssl->flg[CF])
			ssl->res = ft_joinfree(ssl->res, ":", 1);
		if (!(i % 8))
			t++;
	}
}

static void		ft_hashing(t_ssl *ssl, t_64x *sh, uint64_t i, uint64_t j)
{
	while (++i < TW)
		sh->inter[i] = sh->oth[i];
	while (1)
	{
		sh->inter[8] = SIGM(sh->inter[A], 28, 34, 39, 64) +
			((sh->inter[A] & sh->inter[B]) ^ (sh->inter[A] &
			sh->inter[C]) ^ (sh->inter[B] & sh->inter[C]));
		sh->inter[9] = SIGM(sh->inter[E], 14, 18, 41, 64) +
			((sh->inter[E] & sh->inter[F]) ^ ((~ sh->inter[E]) &
			sh->inter[G])) + g_h[j % BLEN] + sh->inter[H] + sh->words[j % BLEN];
		sh->inter[H] = sh->inter[G];
		sh->inter[G] = sh->inter[F];
		sh->inter[F] = sh->inter[E];
		sh->inter[E] = sh->inter[D] + sh->inter[9];
		sh->inter[D] = sh->inter[C];
		sh->inter[C] = sh->inter[B];
		sh->inter[B] = sh->inter[A];
		sh->inter[A] = sh->inter[8] + sh->inter[9];
		ft_debug(ssl, sh, j + 1, BLEN);
		if (!(++j % BLEN))
			break ;
	}
	j = -1;
	while (++j < TW)
		sh->oth[j] += sh->inter[j];
}

static void		ft_hash(t_ssl *ssl, t_64x *sh, uint64_t i, uint64_t j)
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
				sh->words[j] += (uint64_t)ssl->stream[i] << ((7 - i % 8) * 8);
			else
				sh->words[j] += (uint64_t)ssl->end[i - ssl->size]
				<< ((7 - i % 8) * 8);
			j = (!(++i % 8) ? j + 1 : j);
		}
		while (j < BLEN)
		{
			sh->words[j] = sh->words[j - 7] + DELT(sh->words[j - 2], 19, 61, 6,
			64) + DELT(sh->words[j - 15], 1, 8, 7, 64) + sh->words[j - 16];
			j++;
		}
		ft_hashing(ssl, sh, -1, i / 128 * BLEN - BLEN);
	}
}

void			ft_wht_sha(uint64_t *h, int tp)
{
	if (tp < SHA_512_224)
	{
		h[A] = (tp == SHA_512 ? 0x6a09e667f3bcc908 : 0xcbbb9d5dc1059ed8);
		h[B] = (tp == SHA_512 ? 0xbb67ae8584caa73b : 0x629a292a367cd507);
		h[C] = (tp == SHA_512 ? 0x3c6ef372fe94f82b : 0x9159015a3070dd17);
		h[D] = (tp == SHA_512 ? 0xa54ff53a5f1d36f1 : 0x152fecd8f70e5939);
		h[E] = (tp == SHA_512 ? 0x510e527fade682d1 : 0x67332667ffc00b31);
		h[F] = (tp == SHA_512 ? 0x9b05688c2b3e6c1f : 0x8eb44a8768581511);
		h[G] = (tp == SHA_512 ? 0x1f83d9abfb41bd6b : 0xdb0c2e0d64f98fa7);
		h[H] = (tp == SHA_512 ? 0x5be0cd19137e2179 : 0x47b5481dbefa4fa4);
	}
	else
	{
		h[A] = (tp == SHA_512_224 ? 0x8C3D37C819544DA2 : 0x22312194FC2BF72C);
		h[B] = (tp == SHA_512_224 ? 0x73E1996689DCD4D6 : 0x9F555FA3C84C64C2);
		h[C] = (tp == SHA_512_224 ? 0x1DFAB7AE32FF9C82 : 0x2393B86B6F53B151);
		h[D] = (tp == SHA_512_224 ? 0x679DD514582F9FCF : 0x963877195940EABD);
		h[E] = (tp == SHA_512_224 ? 0x0F6D2B697BD44DA8 : 0x96283EE2A88EFFE3);
		h[F] = (tp == SHA_512_224 ? 0x77E36F7304C48942 : 0xBE5E1E2553863992);
		h[G] = (tp == SHA_512_224 ? 0x3F9D85A86A1D36C8 : 0x2B0199FC2C85B8AA);
		h[H] = (tp == SHA_512_224 ? 0x1112E6AD91D692A1 : 0x0EB72DDC81C52CA2);
	}
}

void			ft_sha5(t_ssl *ssl)
{
	t_64x		sh;
	size_t		tm;
	size_t		i;

	tm = ssl->size;
	ssl->sze = (tm % 128 > 111 ? (128 - tm % 128) + 128 : 128 - tm % 128);
	ssl->end = (unsigned char *)ft_strnew(ssl->sze);
	ssl->end[0] = 0x80;
	i = ssl->sze;
	tm *= 8;
	while (--i > ssl->sze - 17)
	{
		ssl->end[i] = tm;
		tm = tm >> 8;
	}
	ft_wht_sha(sh.oth, ssl->type[0]);
	ft_hash(ssl, &sh, 0, 0);
	out_res(ssl, &sh, 0, 0);
}
