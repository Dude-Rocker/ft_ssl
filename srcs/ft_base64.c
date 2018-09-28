/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_base64.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vgladush <vgladush@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/08/31 22:33:27 by vgladush          #+#    #+#             */
/*   Updated: 2018/09/09 16:07:09 by vgladush         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/ft_ssl.h"

static const char g_bs[65] = {
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"};

static void		base_dec(t_ssl *ssl, uint8_t d, size_t i, int j)
{
	ssl->res = ft_strnew(ssl->sze + 1);
	while (ssl->stream[i] && ssl->stream[i] != '=')
	{
		d = 0;
		while (g_bs[d] != ssl->stream[i])
			d++;
		if (!(i % 4))
			ssl->res[j] = d << 2;
		else if (i % 4 == 1)
		{
			ssl->res[j++] += d >> 4;
			ssl->res[j] = d << 4;
		}
		else if (i % 4 == 2)
		{
			ssl->res[j++] += d >> 2;
			ssl->res[j] = d << 6;
		}
		else
			ssl->res[j++] += d;
		i++;
	}
}

static void		base_enc(t_ssl *ssl, int d, size_t i, int j)
{
	while (i < ssl->size)
	{
		d = (uint8_t)ssl->stream[i] >> 2;
		ssl->res[j++] = g_bs[d];
		d = (((uint8_t)ssl->stream[i] << 4) & 63) +
			((uint8_t)ssl->stream[i + 1] >> 4);
		ssl->res[j++] = g_bs[d];
		d = (((uint8_t)ssl->stream[i + 1] << 2) & 60) + (ssl->stream[i + 1] ?
			((uint8_t)ssl->stream[i + 2] >> 6) : 0);
		ssl->res[j++] = g_bs[d];
		d = (ssl->stream[i + 1] ? (uint8_t)ssl->stream[i + 2] & 63 : 0);
		ssl->res[j++] = g_bs[d];
		if (!((j + 1) % 65))
			ssl->res[j++] = '\n';
		i += 3;
	}
	j -= (ssl->res[j - 1] == '\n' ? 3 : 2);
	if (i >= ssl->size + 2)
		ssl->res[j] = '=';
	if (i >= ssl->size + 1)
		ssl->res[j + 1] = '=';
	ssl->res[j + 2] = '\n';
}

void			ft_base64(t_ssl *ssl)
{
	size_t		i;

	i = 0;
	if (ssl->flg[DF])
	{
		ft_kickchar(ssl->stream, ' ', '\t', '\n');
		ssl->size = ft_strlen(ssl->stream);
		ssl->sze = (double)ssl->size * 0.75;
		while (ssl->stream[i] && ft_strchr(g_bs, ssl->stream[i]))
			i++;
		if (i + 2 < ssl->size || (i + 1 < ssl->size && ssl->stream[i + 1] != '=')
			|| (i < ssl->size && ssl->stream[i] != '=') || (ssl->size % 4))
			ssl->res = 0;
		else
			base_dec(ssl, 0, 0, 0);
	}
	else
	{
		ssl->sze = (double)ssl->size / 0.75;
		ssl->sze += 3 - ((ssl->sze + 3) % 4);
		ssl->sze += ssl->sze / 64 + 1;
		ssl->res = ft_strnew(ssl->sze);
		base_enc(ssl, 0, 0, 0);
	}
}
